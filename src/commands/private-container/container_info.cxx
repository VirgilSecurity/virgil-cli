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

#include <virgil/sdk/privatekeys/client/PrivateKeysClient.h>
#include <virgil/sdk/privatekeys/model/ContainerType.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>

using virgil::sdk::privatekeys::client::PrivateKeysClient;
using virgil::sdk::privatekeys::model::ContainerType;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN private_container_info_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Get container-type: easy | normal. ", ' ', virgil::cli_version());

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

        cmd.add(publicKeyIdArg);
        cmd.parse(argc, argv);

        auto publicKeyIdFormat = virgil::cli::parse_pair(publicKeyIdArg.getValue());
        virgil::cli::checkFormatPublicId(publicKeyIdFormat);

        const std::string type = publicKeyIdFormat.first;
        const std::string value = publicKeyIdFormat.second;
        std::string publicKeyId = virgil::cli::getPublicKeyId(type, value);

        PrivateKeysClient privateKeysClient(VIRGIL_APP_TOKEN);
        ContainerType containerType = privateKeysClient.container().getDetails(publicKeyId);
        std::cout << "container_type: " << virgil::sdk::privatekeys::model::toString(containerType) << std::endl;

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "private-container-info. Error: " << exception.error() << " for arg " << exception.argId()
                << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "private-container-info. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
