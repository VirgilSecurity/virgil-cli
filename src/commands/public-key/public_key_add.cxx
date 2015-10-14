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

/**
 * @brief Register user's public key on the Virgil Public Key Service.
 * @return Virgil Public Key
 */
PublicKey register_public_key (const VirgilByteArray& publicKey,
        const std::multimap<std::string, std::string>& userIdsDict, const Credentials& credentials);

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN public_key_add_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Register user's public key on the Virgil Public Keys service.", ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> inPublicKeyArg("i", "in", "Public key. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outVirgilPublicKeyArg("o", "out", "Virgil Public Key. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "private-key", "Sender's private key.",
                false, "", "file");

        TCLAP::ValueArg<std::string> privatePasswordArg("p", "private-pwd", "Sender's private key password",
                false, "", "arg");

        TCLAP::UnlabeledMultiArg<std::string> userIdsArg("user-id",
                "User's identifer.\n"
                "Format: [email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if email, then <value> - user's email;\n"
                "\t* if phone, then <value> - user's phone;\n"
                "\t* if domain, then <value> - user's domain.\n",
                true, "user-id", false);

        cmd.add(userIdsArg);
        cmd.add(privatePasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(outVirgilPublicKeyArg);
        cmd.add(inPublicKeyArg);
        cmd.parse(argc, argv);

        // Read public key
        VirgilByteArray publicKey = virgil::cli::read_bytes(inPublicKeyArg.getValue());

        // Parse user identifiers
        auto userIdsDict = virgil::cli::parse_pair_array(userIdsArg.getValue());

        // Read private key
        VirgilByteArray privateKey = virgil::cli::read_bytes(privateKeyArg.getValue());
        std::string privateKeyPassword = privatePasswordArg.getValue();
        Credentials credentials(privateKey, privateKeyPassword);

        // Register user's public key
        PublicKey virgilPublicKey = register_public_key(publicKey, userIdsDict, credentials);

        // Store Virgil Public Key to the output file
        std::string publicKeyData = Marshaller<PublicKey>::toJson(virgilPublicKey);
        virgil::cli::write_bytes(outVirgilPublicKeyArg.getValue(), publicKeyData);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "public-key-add. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "public-key-add. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

PublicKey register_public_key (const VirgilByteArray& publicKey,
        const std::multimap<std::string, std::string>& userIdsDict, const Credentials& credentials) {

    std::vector<UserData> userIdsData;
    for (const auto& userId: userIdsDict) {
        const std::string type = userId.first;
        const std::string value = userId.second;
        UserData userIdData = UserData().className(UserDataClass::userId).type(type).value(value);
        userIdsData.push_back(userIdData);
    }

    KeysClient keysClient(VIRGIL_APP_TOKEN);
    PublicKey virgilPublicKey = keysClient.publicKey().add(publicKey, userIdsData, credentials, virgil::cli::uuid());
    return  virgilPublicKey;
}
