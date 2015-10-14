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

#include <virgil/sdk/keys/client/KeysClient.h>
#include <virgil/sdk/keys/model/PublicKey.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/uuid.h>

using virgil::sdk::keys::client::KeysClient;
using virgil::sdk::keys::model::PublicKey;

#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN user_data_confirm_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Send confirmation code to the Virgil Public Keys service. "
                "Confirmation code is sent after user's public key registration.", ' ',
                virgil::cli_version());

        TCLAP::ValueArg<std::string> userIdArg("i", "user-data-id",
                "User's data identifer.\n",
                true, "", "arg");

        TCLAP::ValueArg<std::string> confirmationCodeArg("c", "confirmation-code", "Confirmation code.",
                true, "", "arg");

        cmd.add(confirmationCodeArg);
        cmd.add(userIdArg);
        cmd.parse(argc, argv);

        const std::string userDataId = userIdArg.getValue();
        const std::string confirmationCode = confirmationCodeArg.getValue();

        KeysClient keysClient(VIRGIL_APP_TOKEN);
        keysClient.userData().confirm(userDataId, confirmationCode, virgil::cli::uuid());

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "user-data-confirm. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "user-data-confirm. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
