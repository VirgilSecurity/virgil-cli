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

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN public_key_get_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Get user's Virgil Public Key with/without User Data from the Virgil Public Keys service.", ' ',
                virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Virgil Public Key. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> publicKeyIdArg("e", "public-key-id",
                "User identifer.\n"
                "If you want return Virgil Public Key with User Data\n"
                "use format: [public-id]:<value>\n"
                "In other case ( without User Data ):\n"
                "Format: [public-id|email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if public-id, then <value> - user's public-key-id;\n"
                "\t* if email, then <value> - user's email';\n"
                "\t* if phone, then <value> - user's phone;\n"
                "\t* if domain, then <value> - user's domain.\n",
                true, "", "arg");

        TCLAP::SwitchArg isUserDataArg("w", "with-user-data", "If true - get user's Virgil Public Key with User Data."
                " Default false. ",false);

        TCLAP::ValueArg<std::string> privateKeyArg("k", "private-key", "Recipient's private key.",
                false, "", "file");

        TCLAP::ValueArg<std::string> privatePasswordArg("p", "private-pwd", "Recipient's private key password",
                false, "", "arg");

        cmd.add(privatePasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(isUserDataArg);
        cmd.add(publicKeyIdArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        const auto publicKeyIdFormat = virgil::cli::parse_pair(publicKeyIdArg.getValue());
        virgil::cli::checkFormatPublicId(publicKeyIdFormat);
        const std::string type = publicKeyIdFormat.first;
        const std::string value = publicKeyIdFormat.second;

        KeysClient keysClient(VIRGIL_APP_TOKEN);
        PublicKey virgilPublicKey;

        if ( isUserDataArg.getValue() == false ) {
            if (type == "public-id") {
                std::string publicKeyId = value;
                virgilPublicKey = keysClient.publicKey().get(publicKeyId);

            } else {
                std::string userId = value;
                virgilPublicKey = keysClient.publicKey().grab(userId, virgil::cli::uuid());
            }
        } else {
            if (type == "public-id") {
                std::string publicKeyId = value;

                // Read private key
                VirgilByteArray privateKey = virgil::cli::read_bytes(privateKeyArg.getValue());
                std::string privateKeyPassword = privatePasswordArg.getValue();
                Credentials credentials(publicKeyId, privateKey, privateKeyPassword);

                virgilPublicKey = keysClient.publicKey().grab(credentials, virgil::cli::uuid());
            } else {
                std::string errorMessage = "can not use " + publicKeyIdArg.getValue() + "with isUserDataArg=true.";
                errorMessage += "You should use format: [public-key-id]:<value>";
                throw std::invalid_argument(errorMessage);
            }
        }

        // Store Virgil Public Key to the output file
        std::string publicKeyData = Marshaller<PublicKey>::toJson(virgilPublicKey);

        // Prepare output
        virgil::cli::write_bytes(outArg.getValue(), publicKeyData);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "public-key-get. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "public-key-get. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
