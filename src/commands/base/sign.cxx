/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamSigner.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>

#include <cli/version.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>
#include <cli/wrapper/sdk/PrivateKey.h>

namespace vcrypto = virgil::crypto;
namespace wsdk = cli::wrapper::sdk;

int sign_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Sign plain.txt with private key:\n"
            "\tvirgil sign -i plain.txt -o plain.txt.sign -k private.key\n\n",

            "2. Sign plain.txt with private key:\n"
            "\tvirgil sign -i plain.txt -o plain.txt.sign -k private.key -p STRONGPASS\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kSign_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", cli::kSign_Input_Description, false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", cli::kSign_Output_Description, false, "", "file");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "key", "Signer's Private Key.", true, "", "file");

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            cli::kPrivateKeyPassword_ShortName, cli::kPrivateKeyPassword_LongName, cli::kPrivateKeyPassword_Description,
            false, "", cli::kPrivateKeyPassword_TypeDesc);

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(privateKeyArg);
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
                throw std::invalid_argument("cannot read file: " + inArg.getValue());
            }
            inStream = &inFile;
        }

        // Read private key
        vcrypto::VirgilByteArray privateKey = wsdk::readPrivateKey(privateKeyArg.getValue());
        vcrypto::VirgilByteArray privateKeyPassword;
        if (privateKeyPasswordArg.isSet()) {
            privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
        } else {
            privateKeyPassword = cli::setPrivateKeyPass(privateKey);
        }

        // Create signer
        vcrypto::VirgilStreamSigner signer;

        // Sign data
        vcrypto::stream::VirgilStreamDataSource dataSource(*inStream);
        vcrypto::VirgilByteArray sign = signer.sign(dataSource, privateKey, privateKeyPassword);

        // Prepare output. Write sign to the output.
        cli::writeBytes(outArg.getValue(), sign);

        if (verboseArg.isSet()) {
            std::cout << "File signed" << std::endl;
        }
    } catch (TCLAP::ArgException& exception) {
        std::cerr << "sign. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "sign. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
