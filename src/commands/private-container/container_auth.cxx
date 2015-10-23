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
#include <stdexcept>
#include <string>

#include <tclap/CmdLine.h>

#include <virgil/sdk/privatekeys/client/PrivateKeysClient.h>
#include <virgil/sdk/privatekeys/model/UserData.h>
#include <virgil/sdk/privatekeys/model/UserDataClass.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>

using virgil::sdk::privatekeys::client::PrivateKeysClient;
using virgil::sdk::privatekeys::model::UserData;
using virgil::sdk::privatekeys::model::UserDataClass;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN private_container_auth_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Authenticate a session. Note:  Before logging in, make sure that you have already "
                "initialized the Container  in Virgil's Private Key service. Use the same confirmed User Data "
                "identity parameter as you registered in our Public Keys service. ", ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "An authentication token. If omitted stdout is used.",
                false, "", "file");        

        TCLAP::ValueArg<std::string> userIdArg("u","user-id",
                "User's identifer.\n"
                "Format:\n"
                "[email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if email, then <value> - user's email;\n"
                "\t* if phone, then <value> - user's phone;\n"
                "\t* if domain, then <value> - user's domain.\n",
                true, "","arg" );

        TCLAP::ValueArg<std::string> containerPaswordArg("c", "container-pwd", "Container password.",
                true, "", "arg");

        cmd.add(containerPaswordArg);
        cmd.add(userIdArg);
        cmd.add(outArg);        
        cmd.parse(argc, argv);

        const auto userId = virgil::cli::parse_pair(userIdArg.getValue());
        virgil::cli::checkFormatUserId(userId);
        const std::string type = userId.first;
        const std::string value = userId.second;
        const UserData userData = virgil::cli::getUserData(type, value);

        const std::string containerPassword = containerPaswordArg.getValue();

        PrivateKeysClient privateKeysClient(VIRGIL_APP_TOKEN);
        std::string authToken = privateKeysClient.auth().getAuthToken(userData, containerPassword);

        // Prepare output. Output an authentication token.
        virgil::cli::write_bytes(outArg.getValue(), authToken);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "private-container-auth. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "private-container-auth. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
