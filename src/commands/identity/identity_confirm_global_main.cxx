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
#include <fstream>

#include <tclap/CmdLine.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>
#include <cli/InputShadow.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

int identity_confirm_global_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Identity confirmation with requests number limit = 2 and time validity limit = 3600:\n"
            "\tvirgil identity-confirm-global -d email:alice@domain.com -o alice/validated-identity.txt\n\n",

            "2. Identity confirmation with requests number limit = 10 and time validity limit = 60:\n"
            "\tvirgil identity-confirm-global -d email:alice@domain.com -t 60 -c 10 -o "
            "alice/validated-identity.txt\n\n",

            "3. Identity confirmation with requests number limit = 2 and time validity limit = 3600:\n"
            "\tvirgil identity-confirm-global --action-id alice/action_id.txt --confirmation-code <code>"
            " -o alice/validated-identity.txt\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kIdentityConfirmGlobal_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Validated identity. If omitted, stdout is used.", false, "",
                                            "file");

        TCLAP::ValueArg<std::string> identityArg(cli::kIdentity_ShortName, cli::kIdentity_LongName,
                                                 cli::kGlobalIdentity_Description, false, "", cli::kIdentity_TypedDesc);

        TCLAP::ValueArg<std::string> actionIdArg("", "action-id", "Action id.", false, "", "file");

        TCLAP::ValueArg<std::string> confirmationCodeArg("", "confirmation-code", "Confirmation code", false, "",
                                                         "arg");

        TCLAP::ValueArg<int> timeToliveArg("t", "time-to-live", "Time to live, by default = 3600.", false, 3600, "int");

        TCLAP::ValueArg<int> countToLiveArg("c", "count-to-live", "Count to live, by default = 2.", false, 2, "int");

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(countToLiveArg);
        cmd.add(timeToliveArg);
        cmd.add(confirmationCodeArg);
        cmd.add(actionIdArg);
        cmd.add(identityArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        cli::ConfigFile configFile = cli::readConfigFile();
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.getServiceUri());
        std::string recipientType;
        std::string recipientValue;

        std::string actionId;
        std::string confirmationCode;

        if (actionIdArg.isSet() && confirmationCodeArg.isSet()) {
            std::ifstream inFileActionId(actionIdArg.getValue(), std::ios::binary);
            if (!inFileActionId) {
                throw std::invalid_argument("can not read file with action id by path: " + actionIdArg.getValue());
            }

            actionId = std::string((std::istreambuf_iterator<char>(inFileActionId)), std::istreambuf_iterator<char>());
            confirmationCode = confirmationCodeArg.getValue();

        } else if (!actionIdArg.isSet() && !confirmationCodeArg.isSet()) {

            if (identityArg.isSet()) {
                auto identityPair = cli::parsePair(identityArg.getValue());
                recipientType = identityPair.first;
                recipientValue = identityPair.second;
                std::string arg = "-d, --identity";
                cli::checkFormatIdentity(arg, recipientType);

                if (verboseArg.isSet()) {
                    std::cout << "Send confirmation-code to " << recipientValue << std::endl;
                }
                actionId = servicesHub.identity().verify(recipientValue, vsdk::dto::VerifiableIdentityType::Email);

                std::cout << "Enter confirmation code that was sent on - " << recipientType << ":" << recipientValue
                          << std::endl;
                confirmationCode = cli::inputShadow();

            } else {
                throw std::invalid_argument("-d, --identity -- is not set");
            }
        } else {
            throw std::invalid_argument("--action-id and --confirmation-code must always together");
        }

        if (verboseArg.isSet()) {
            std::cout << "Confirme identity " << recipientValue << std::endl;
        }

        auto validatedIdentity = servicesHub.identity().confirm(actionId, confirmationCode, timeToliveArg.getValue(),
                                                                countToLiveArg.getValue());

        std::string validatedIdentityStr =
            vsdk::io::Marshaller<vsdk::dto::ValidatedIdentity>::toJson<4>(validatedIdentity);

        cli::writeBytes(outArg.getValue(), validatedIdentityStr);

        if (verboseArg.isSet()) {
            std::cout << "Identity " << recipientType << ":" << recipientValue << "  is confirmed." << std::endl;
            std::cout << "Time to live: " << timeToliveArg.getValue() << std::endl;
            std::cout << "Count to live: " << countToLiveArg.getValue() << std::endl;
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "identity-confirm-global. Error: " << exception.error() << " for arg " << exception.argId()
                  << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "identity-confirm-global. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
