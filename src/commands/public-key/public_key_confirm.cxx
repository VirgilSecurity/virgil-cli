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
#include <vector>

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
#define MAIN public_key_confirm_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Confirms the reset or delete a Public Key operation from the Virgil Public Keys service. ",
                ' ', virgil::cli_version());

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

        TCLAP::ValueArg<std::string> actionTokenArg("t", "action-token", "Action token.",
                true, "", "arg");

        TCLAP::SwitchArg isResetArg("r", "reset",
                "-r, --reset - default false.\n"
                "If false - confirms delete Public Key operation.\n"
                "If true - confirms reset Public Key operation.\n",
                false);

        TCLAP::ValueArg<std::string> privateKeyArg("k", "private-key", "Sender's private key.",
                false, "", "file");

        TCLAP::ValueArg<std::string> privatePasswordArg("p", "private-pwd", "Sender's private key password",
                false, "", "arg");

        TCLAP::UnlabeledMultiArg<std::string> confirmCodesArg("confirm-codes",
                "Confirmation codes.", true, "codes", true);

        cmd.add(confirmCodesArg);
        cmd.add(privatePasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(isResetArg);
        cmd.add(actionTokenArg);
        cmd.add(publicKeyIdArg);
        cmd.parse(argc, argv);

        const auto publicKeyIdFormat = virgil::cli::parse_pair(publicKeyIdArg.getValue());
        virgil::cli::checkFormatPublicId(publicKeyIdFormat);

        const std::string type = publicKeyIdFormat.first;
        const std::string value = publicKeyIdFormat.second;
        const std::string oldPublicKeyId = virgil::cli::getPublicKeyId(type, value);

        const std::string actionToken = actionTokenArg.getValue();
        const std::vector<std::string> confirmCodes = confirmCodesArg.getValue();

        KeysClient keysClient(VIRGIL_APP_TOKEN);

        if ( isResetArg.getValue() == false ) {
            // Confirm Delete Public Key
            keysClient.publicKey().confirmDel(oldPublicKeyId, actionToken, confirmCodes);
        } else {
            // Read private key
            VirgilByteArray newPrivateKey = virgil::cli::read_bytes(privateKeyArg.getValue());
            std::string newPrivateKeyPassword = privatePasswordArg.getValue();
            Credentials newKeyCredentials(newPrivateKey, newPrivateKeyPassword);

            // Confirm Reset Public Key
            keysClient.publicKey().confirmReset(oldPublicKeyId, newKeyCredentials, actionToken, confirmCodes);
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "public-key-confirm. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "public-key-confirm. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
