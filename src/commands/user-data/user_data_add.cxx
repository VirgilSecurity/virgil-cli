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
#include <string>
#include <stdexcept>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/keys/client/Credentials.h>
#include <virgil/sdk/keys/client/KeysClient.h>
#include <virgil/sdk/keys/io/Marshaller.h>
#include <virgil/sdk/keys/model/PublicKey.h>
#include <virgil/sdk/keys/model/UserData.h>
#include <virgil/sdk/keys/model/UserDataClass.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/uuid.h>

using virgil::crypto::VirgilByteArray;

using virgil::sdk::keys::client::Credentials;
using virgil::sdk::keys::client::KeysClient;
using virgil::sdk::keys::io::Marshaller;
using virgil::sdk::keys::model::PublicKey;
using virgil::sdk::keys::model::UserData;
using virgil::sdk::keys::model::UserDataClass;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN user_data_add_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Add user data email|phone|domain. ", ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> publicKeyIdArg("e", "public-key-id",
                "Sender's public key id."
                "[public-id|file|email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if public-id, then <value> - sender's public-id;\n"
                "\t* if file, then <value> - sender's Virgil Public Key file stored locally;\n"
                "\t* if email, then <value> - sender's email;\n"
                "\t* if phone, then <value> - sender's phone;\n"
                "\t* if domain, then <value> - sender's domain.\n",
                true, "", "arg");

        TCLAP::ValueArg<std::string> userIdArg("u","user-id",
                "User's identifer.\n"
                "Format:\n"
                "[email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if email, then <value> - user's email;\n"
                "\t* if phone, then <value> - user's phone;\n"
                "\t* if domain, then <value> - user's domain.\n",
                true, "","arg" );

        TCLAP::ValueArg<std::string> privateKeyArg("k", "private-key", "Sender's private key.",
                true, "", "file");

        TCLAP::ValueArg<std::string> privatePasswordArg("p", "private-pwd", "Sender's private key password.",
                false, "", "arg");

        cmd.add(privatePasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(userIdArg);
        cmd.add(publicKeyIdArg);
        cmd.parse(argc, argv);

        const auto newUserId = virgil::cli::parse_pair(userIdArg.getValue());
        virgil::cli::checkFormatUserId(newUserId);
        const std::string typeNewUser = newUserId.first;
        const std::string valueNewUser = newUserId.second;

        UserData userData = UserData()
                .className(UserDataClass::userId)
                .type(typeNewUser)
                .value(valueNewUser);

        const auto publicKeyIdFormat = virgil::cli::parse_pair(publicKeyIdArg.getValue());
        virgil::cli::checkFormatPublicId(publicKeyIdFormat);
        std::string publicKeyId = virgil::cli::getPublicKeyId(publicKeyIdFormat.first, publicKeyIdFormat.second);

        // Read private key
        const VirgilByteArray privateKey = virgil::cli::read_bytes(privateKeyArg.getValue());
        const std::string privateKeyPassword = privatePasswordArg.getValue();
        const Credentials credentials(publicKeyId, privateKey, privateKeyPassword);

        KeysClient keysClient(VIRGIL_APP_TOKEN);
        UserData userDataResponse = keysClient
                .userData()
                .add(userData, credentials, virgil::cli::uuid());

        std::string data = Marshaller<UserData>::toJson(userDataResponse);
        std::cout << data << std::endl;

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "user-data-add. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "user-data-add. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
