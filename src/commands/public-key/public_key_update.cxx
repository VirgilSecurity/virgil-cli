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
#define MAIN public_key_update_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Update user's public key on the Virgil Public Keys service. ", ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "New Public key. If omitted stdin is used.",
                false, "", "file");

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

        TCLAP::ValueArg<std::string> oldPrivateKeyArg("k", "private-key", "Sender's old private key.",
                true, "", "file");

        TCLAP::ValueArg<std::string> oldPrivatePasswordArg("p", "private-pwd", "Sender's old private key password.",
                false, "", "arg");

        TCLAP::ValueArg<std::string> newPrivateKeyArg("", "new-private-key", "Sender's new private key.",
                true, "", "file");

        TCLAP::ValueArg<std::string> newPrivatePasswordArg("", "new-private-pwd", "Sender's new private key password.",
                false, "", "arg");

        cmd.add(newPrivatePasswordArg);
        cmd.add(newPrivateKeyArg);
        cmd.add(oldPrivatePasswordArg);
        cmd.add(oldPrivateKeyArg);
        cmd.add(publicKeyIdArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);

        // Read new public key
        VirgilByteArray newPublicKey = virgil::cli::read_bytes(inArg.getValue());

        // Read new private key
        VirgilByteArray newPrivateKey = virgil::cli::read_bytes(newPrivateKeyArg.getValue());
        std::string newPrivateKeyPassword = newPrivatePasswordArg.getValue();

        Credentials newKeyCredentials(newPrivateKey, newPrivateKeyPassword);

        const auto publicKeyIdFormat = virgil::cli::parse_pair(publicKeyIdArg.getValue());
        virgil::cli::checkFormatPublicId(publicKeyIdFormat);

        const std::string type = publicKeyIdFormat.first;
        const std::string value = publicKeyIdFormat.second;

        // Get Old public key
        std::string oldPublicKeyId = virgil::cli::getPublicKeyId(type, value);

        // Read old private key
        VirgilByteArray oldPrivateKey = virgil::cli::read_bytes(oldPrivateKeyArg.getValue());
        std::string oldPrivateKeyPassword = oldPrivatePasswordArg.getValue();
        Credentials oldKeyCredentials(oldPublicKeyId, oldPrivateKey, oldPrivateKeyPassword);

        // Update Public Key
        KeysClient keysClient(VIRGIL_APP_TOKEN);
        keysClient.publicKey().update(newPublicKey, newKeyCredentials, oldKeyCredentials, virgil::cli::uuid());

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "private-container-update. Error: " << exception.error() << " for arg " << exception.argId()
                << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "private-container-update. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
