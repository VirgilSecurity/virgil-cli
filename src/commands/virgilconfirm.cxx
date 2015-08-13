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

#include <virgil/sdk/keys/http/Connection.h>
#include <virgil/sdk/keys/model/UserData.h>
#include <virgil/sdk/keys/client/KeysClient.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/util.h>
#include <cli/pair.h>
#include <cli/guid.h>

using virgil::sdk::keys::http::Connection;
using virgil::sdk::keys::model::UserData;
using virgil::sdk::keys::client::KeysClient;


#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN confirm_main
#endif


int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Send confirmation code to the Virgil Public Keys service. "
                "Confirmation code is sent after user's public key registration.", ' ',
                virgil::cli_version());

        TCLAP::ValueArg<std::string> userIdArg("i", "user-id",
                "User's identifer.\n"
                "Format: [email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if email, then <value> - user's email;\n"
                "\t* if phone, then <value> - user's phone;\n"
                "\t* if domain, then <value> - user's domain.\n",
                true, "", "arg");

        TCLAP::ValueArg<std::string> confirmationCodeArg("c", "code", "Confirmation code.",
                true, "", "arg");

        cmd.add(confirmationCodeArg);
        cmd.add(userIdArg);

        cmd.parse(argc, argv);

        // Parse User Identifier
        const std::pair<std::string, std::string> userIdPair = virgil::cli::parse_pair(userIdArg.getValue());
        const std::string userIdType = userIdPair.first;
        const std::string userId = userIdPair.second;

        // Find User Data
        KeysClient keysClient(std::make_shared<Connection>(VIRGIL_APP_TOKEN));
        auto foundUserDatas = keysClient.userData().search(userId, userIdType);

        // Confirm User Data
        if (foundUserDatas.size() > 0) {
            UserData userData = foundUserDatas.front();
            keysClient.userData().confirm(userData.userDataId(), confirmationCodeArg.getValue(), virgil::cli::guid());
        } else {
            throw std::runtime_error("User with id: " + userIdArg.getValue() + " not found.");
        }
    } catch (TCLAP::ArgException& exception) {
        std::cerr << "Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
