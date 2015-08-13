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

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <string>

#include <tclap/CmdLine.h>

#include <virgil/sdk/keys/model/PublicKey.h>
#include <virgil/sdk/keys/io/marshaller.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>

using virgil::sdk::keys::model::PublicKey;
using virgil::sdk::keys::io::marshaller;


#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN keyget_main
#endif


int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Get user's Virgil Public Key from the Virgil Public Keys service.", ' ',
                virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Virgil Public Key. If omitted stdout is used.",
                false, "", "file");

        TCLAP::UnlabeledValueArg<std::string> userIdArg("user-id",
                "User identifer.\n"
                "Format: [email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if email, then <value> - user's email;\n"
                "\t* if phone, then <value> - user's phone;\n"
                "\t* if domain, then <value> - user's domain.\n",
                true, "", "user-id", false);

        cmd.add(userIdArg);
        cmd.add(outArg);

        cmd.parse(argc, argv);

        // Get user's Virgil Public Key
        const std::pair<std::string, std::string> recipient = virgil::cli::parse_pair(userIdArg.getValue());
        const std::string recipientIdType = recipient.first;
        const std::string recipientId = recipient.second;
        PublicKey virgilPublicKey = virgil::cli::get_virgil_public_key(recipientId, recipientIdType);

        // Store Virgil Public Key to the output file
        std::string publicKeyData = marshaller<PublicKey>::toJson(virgilPublicKey);

        // Prepare output
        virgil::cli::write_bytes(outArg.getValue(), publicKeyData);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
