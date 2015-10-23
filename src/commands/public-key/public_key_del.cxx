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
#include <virgil/sdk/keys/model/PublicKey.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/uuid.h>

using virgil::crypto::VirgilByteArray;

using virgil::sdk::keys::client::Credentials;
using virgil::sdk::keys::client::KeysClient;
using virgil::sdk::keys::model::PublicKey;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN public_key_del_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Delete public key. "
                "The purpose is to remove a Public Key’s data. "
                "\nNote:\n"
                "If -c, --confirm - true is used, the Public Key will be removed immediately "
                "without anyconfirmation.\n"
                "If -c, --confirm - false is used, confirmation is required. The action will return an"
                "action_token response object and will send confirmation tokens to all of the Public Key’s confirmed"
                "UDIDs. The list of masked UDID’s will be returned in user_ids response object property. To commit a "
                "Public Key remove call 'user-data-confirm' action with action_token value and the list of "
                "confirmation codes.", ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> publicKeyIdArg("e", "public-key-id",
                "Sender's public key id.\n"
                "Format:\n"
                "[public-id|file|email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if public-id, then <value> - sender's public-id;\n"
                "\t* if file, then <value> - sender's Virgil Public Key file stored locally;\n"
                "\t* if email, then <value> - sender's email;\n"
                "\t* if phone, then <value> - sender's phone;\n"
                "\t* if domain, then <value> - sender's domain.\n",
                true, "", "arg");

        TCLAP::SwitchArg isConfirmArg("c", "confirm",
                "Public Key will be removed immediately without anyconfirmation.\n"
                "If omitted - Public Key confirmation is required.\n",
                false);

        TCLAP::ValueArg<std::string> privateKeyArg("k", "private-key", "Sender's private key." 
                "If --confirm - required.", false , "", "file");        

        TCLAP::ValueArg<std::string> privatePasswordArg("p", "private-pwd", "Sender's private key password.",
                false, "", "arg");

        cmd.add(privatePasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(isConfirmArg);
        cmd.add(publicKeyIdArg);
        cmd.parse(argc, argv);

        const auto publicKeyIdFormat = virgil::cli::parse_pair(publicKeyIdArg.getValue());
        virgil::cli::checkFormatPublicId(publicKeyIdFormat);
        const std::string type = publicKeyIdFormat.first;
        const std::string value = publicKeyIdFormat.second;
        std::string publicKeyId = virgil::cli::getPublicKeyId(type, value);

        KeysClient keysClient(VIRGIL_APP_TOKEN);

        if ( isConfirmArg.getValue() == false ) {
            // Public Key Delete
            std::string confirmInfo = keysClient.publicKey().del(publicKeyId, virgil::cli::uuid());
            std::cout << confirmInfo << std::endl;
        } else {
            if (privateKeyArg.getValue().empty()) {
                std::string errorMes = 
                        "PARSE ERROR: \n"
                        "Required argument missing: private-key\n";

                throw std::invalid_argument(errorMes);
            }

            // Read private key
            VirgilByteArray privateKey = virgil::cli::read_bytes(privateKeyArg.getValue());
            std::string privateKeyPassword = privatePasswordArg.getValue();
            Credentials credentials(publicKeyId, privateKey, privateKeyPassword);
            
            // Public Key Delete
            keysClient.publicKey().del(credentials, virgil::cli::uuid());
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "public-key-del. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "public-key-del. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
