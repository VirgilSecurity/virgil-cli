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

#include <stdexcept>
#include <string>

#include <tclap/CmdLine.h>

#include <virgil/sdk/keys/client/KeysClient.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>

using virgil::sdk::keys::client::KeysClient;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN public_key_id_get_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Get user's Public Key Id from the Virgil Public Keys service.", ' ',
                virgil::cli_version());

        TCLAP::ValueArg<std::string> outPublicKeyIdArg("o", "out", "Output Public Key Id. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> userIdArg("u","user-id",
                "User's identifer.\n"
                "Format: [email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if email, then <value> - user's email;\n"
                "\t* if phone, then <value> - user's phone;\n"
                "\t* if domain, then <value> - user's domain.\n",
                true, "","arg" );

        cmd.add(userIdArg);
        cmd.add(outPublicKeyIdArg);
        cmd.parse(argc, argv);

        const auto userId = virgil::cli::parse_pair(userIdArg.getValue());
        virgil::cli::checkFormatUserId(userId);
        const std::string typeUserId = userId.first;
        const std::string valueUserId = userId.second;

        std::string publicKeyId = virgil::cli::getPublicKeyId(typeUserId, valueUserId);
        virgil::cli::write_bytes(outPublicKeyIdArg.getValue(), publicKeyId);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "public-key-id-get. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "public-key-id-get. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
