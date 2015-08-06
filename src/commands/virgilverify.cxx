/**
 * Copyright (C) 2015 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamSigner.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>

#include <virgil/sdk/keys/model/PublicKey.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilStreamSigner;
using virgil::crypto::stream::VirgilStreamDataSource;

using virgil::sdk::keys::model::PublicKey;


#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN verify_main
#endif

int MAIN(int argc, char **argv)
{
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Verify data with given user's identifier or with it Virgil Public Key.", ' ',
                virgil::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be verified. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out",
                "Verification result: success | failure. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> signArg("s", "sign", "Digest sign.",
                true, "", "file");

        TCLAP::ValueArg<std::string> signOwnerArg("r", "sign-owner",
                "Sign owner, defined in format:"
                "[file|email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if file, then <value> - signers's Virgil Public Key file stored locally;\n"
                "\t* if email, then <value> - signers's email;\n"
                "\t* if phone, then <value> - signers's phone;\n"
                "\t* if domain, then <value> - signers's domain.\n",
                true, "", "arg");


        cmd.add(signOwnerArg);
        cmd.add(signArg);
        cmd.add(outArg);
        cmd.add(inArg);

        cmd.parse(argc, argv);

        // Prepare input
        std::istream* inStream;
        std::ifstream inFile;
        if (inArg.getValue().empty() || inArg.getValue() == "-") {
            inStream = &std::cin;
        } else {
            inFile.open(inArg.getValue(), std::ios::in | std::ios::binary);
            if (!inFile) {
                throw std::invalid_argument("can not read file: " + inArg.getValue());
            }
            inStream = &inFile;
        }

        // Verify data
        VirgilStreamDataSource dataSource(*inStream);

        // Read sign
        std::ifstream signFile(signArg.getValue(), std::ios::in | std::ios::binary);
        if (!signFile) {
            throw std::invalid_argument("can not read file: " + signArg.getValue());
        }

        VirgilByteArray sign((std::istreambuf_iterator<char>(signFile)), std::istreambuf_iterator<char>());

        const std::pair<std::string, std::string> recipient = virgil::cli::parse_pair(signOwnerArg.getValue());
        const std::string recipientIdType = recipient.first;
        const std::string recipientId = recipient.second;

        PublicKey publicKey;
        if(recipientIdType == "file") {
            // Read Virgil Public Key
            std::ifstream virgilPublicKeyFile(recipientId, std::ios::in | std::ios::binary);
            if (!virgilPublicKeyFile) {
                throw std::invalid_argument("can not read Virgil Public Key: " + recipientId);
            }
            publicKey = virgil::cli::read_virgil_public_key(virgilPublicKeyFile);

        } else {
            // Get Virgil Public Key from the service
           publicKey = virgil::cli::get_virgil_public_key(recipientId, recipientIdType);
        }

        // Create signer
        VirgilStreamSigner signer;
        bool verified = signer.verify(dataSource, sign, publicKey.key());
        if (verified) {
            virgil::cli::write_bytes(outArg.getValue(), "success");
            return EXIT_SUCCESS;
        } else {
            virgil::cli::write_bytes(outArg.getValue(), "failure");
            return EXIT_FAILURE;
        }
    } catch (TCLAP::ArgException& exception) {
        std::cerr << "Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }
}
