/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#include <tclap/CmdLine.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>
#include <cli/wrapper/sdk/ValidatedIdentity.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;
namespace wsdk = cli::wrapper::sdk;

int private_key_get_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Get private key from Private Key Service:\n"
            "\tvirgil private-key-get -a <card_id> -f alice/validated_identity.txt -o alice/private.key\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kPrivateKeyGet_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Private Key. If omitted, stdout is used.", false, "", "file");

        TCLAP::ValueArg<std::string> cardIdArg(cli::kCardId_ShortName, cli::kCardId_LongName, cli::kCardId_Description,
                                               true, "", cli::kCardId_TypeDesc);

        TCLAP::ValueArg<std::string> validatedIdentityArg("f", "validated-identity",
                                                          "Validated Identity for Private Virgil Card - see 'virgil "
                                                          "identity-confirm-private', for Global Virgil Card - see "
                                                          "'virgil identity-confirm-global'",
                                                          true, "", "file");

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(validatedIdentityArg);
        cmd.add(cardIdArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        std::string cardId = cardIdArg.getValue();
        vsdk::dto::ValidatedIdentity validatedIdentity = wsdk::readValidatedIdentity(validatedIdentityArg.getValue());

        cli::ConfigFile configFile = cli::readConfigFile();
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.getServiceUri());

        vsdk::models::PrivateKeyModel privateKey = servicesHub.privateKey().get(cardId, validatedIdentity);
        std::string privateKeyStr = vsdk::io::Marshaller<vsdk::models::PrivateKeyModel>::toJson<4>(privateKey);
        cli::writeBytes(outArg.getValue(), privateKeyStr);

        if (verboseArg.isSet()) {
            std::cout << "Private key connected with the Card containing card-id:" << cardIdArg.getValue()
                      << " has been received" << std::endl;
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "private-key-get. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "private-key-get. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
