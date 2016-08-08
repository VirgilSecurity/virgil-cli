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

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

int card_search_global_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{"1. Search for global Virgil Card by user's email:\n"
                                          "\tvirgil card-search-global -e alice@mailinator.com\n\n",

                                          "2. Search for application global Virgil Card by application name:\n"
                                          "\tvirgil card-search-global -c <app_name>\n\n",

                                          "3. Get all application Cards:\n"
                                          "\tvirgil card-search-global -c \"com.virgilsecurity.*\"\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kCardSearchGlobal_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Folder where Virgil Cards will be saved.", false, "", "arg");

        TCLAP::ValueArg<std::string> applicationNameArg(
            "c", "application-name", "Application name, name = 'com.virgilsecurity.*' - get all Cards\n", true, "",
            "arg");

        TCLAP::ValueArg<std::string> emailArg("e", "email", "email", true, "", "arg");

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.xorAdd(emailArg, applicationNameArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        cli::ConfigFile configFile = cli::readConfigFile();
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.getServiceUri());
        std::vector<vsdk::models::CardModel> appCards;
        if (applicationNameArg.isSet()) {
            appCards =
                servicesHub.card().searchGlobal(applicationNameArg.getValue(), vsdk::dto::IdentityType::Application);
            if (appCards.empty()) {
                if (verboseArg.isSet()) {
                    std::cout << "Card(s) by application name: " << applicationNameArg.getValue()
                              << " haven't been found." << std::endl;
                }
            }

        } else {
            appCards = servicesHub.card().searchGlobal(emailArg.getValue(), vsdk::dto::IdentityType::Email);
            if (appCards.empty()) {
                if (verboseArg.isSet()) {
                    std::cout << "Card(s) by email: " << emailArg.getValue() << " haven't been found." << std::endl;
                }
                return EXIT_SUCCESS;
            }
        }

        std::string pathTofolder = outArg.getValue();
        if (pathTofolder.empty()) {
            for (auto&& appCard : appCards) {
                std::string appCardStr = vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(appCard);
                cli::writeBytes(pathTofolder, appCardStr);
            }
        } else {
            for (auto&& appCard : appCards) {
                std::string identity = appCard.getCardIdentity().getValue();
                std::string cardId = appCard.getId();

                std::string fileName = identity + "-id-" + appCard.getId() + ".vcard";
                std::string appCardStr = vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(appCard);
                cli::writeBytes(pathTofolder + "/" + fileName, appCardStr);
            }
        }

        if (verboseArg.isSet()) {
            if (applicationNameArg.isSet()) {
                std::cout << "For the entered application name:" << applicationNameArg.getValue()
                          << " have been received " << appCards.size() << " Cards." << std::endl;
            } else {
                // emailArg.isSet
                std::cout << "For the entered email:" << emailArg.getValue() << " have been received "
                          << appCards.size() << " Cards." << std::endl;
            }
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "card-search-global. Error: " << exception.error() << " for arg " << exception.argId()
                  << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "card-search-global. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
