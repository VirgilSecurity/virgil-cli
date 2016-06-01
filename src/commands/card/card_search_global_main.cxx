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

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;
namespace vcli = virgil::cli;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN card_search_global_main
#endif

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Search for a Global Virgil Card from the Virgil Keys Service by:.\n"
                                  "1. application_name - search an application Virgil Global Card\n"
                                  "2. email - search a Virgil Global Card\n";

        std::vector<std::string> examples;
        examples.push_back("The global search for application Cards by email:\n"
                           "virgil card-search-global -e alice@mailinator.com\n\n");

        examples.push_back("The global search for application Global Virgil Cards by application name:\n"
                           "virgil card-search-global -c <app_name>\n\n");

        examples.push_back("Get all application cards:\n"
                           "virgil card-search-global -c \"com.virgilsecurity.*\"\n\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Folder in which will be saved a Virgil Cards", false, "",
                                            "arg");

        TCLAP::ValueArg<std::string> applicationNameArg(
            "c", "application-name", "Application name, name = 'com.virgilsecurity.*' - get all Cards\n", true, "",
            "arg");

        TCLAP::ValueArg<std::string> emailArg("e", "email", "email", true, "", "arg");

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Show detailed information", false);

        cmd.add(verboseArg);
        cmd.xorAdd(emailArg, applicationNameArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        vcli::ConfigFile configFile = vcli::readConfigFile(verboseArg.isSet());
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.serviceUri);
        std::vector<vsdk::models::CardModel> appCards;
        if (applicationNameArg.isSet()) {
            appCards =
                servicesHub.card().searchGlobal(applicationNameArg.getValue(), vsdk::dto::IdentityType::Application);
        } else {
            appCards = servicesHub.card().searchGlobal(emailArg.getValue(), vsdk::dto::IdentityType::Email);
        }

        if (appCards.empty()) {
            if (verboseArg.isSet()) {
                std::cout << "Card[s] by name: " << applicationNameArg.getValue() << " haven't been found."
                          << std::endl;
            }
            return EXIT_FAILURE;
        }

        std::string pathTofolder = outArg.getValue();
        if (pathTofolder.empty()) {
            for (auto&& appCard : appCards) {
                std::string appCardStr = vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(appCard);
                vcli::writeBytes(pathTofolder, appCardStr);
            }
        } else {
            for (auto&& appCard : appCards) {
                std::string identity = appCard.getCardIdentity().getValue();
                std::string cardId = appCard.getId();

                std::string fileName = identity + "-id-" + appCard.getId() + ".vcard";
                std::string appCardStr = vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(appCard);
                vcli::writeBytes(pathTofolder + "/" + fileName, appCardStr);
            }
        }

        if (verboseArg.isSet()) {
            std::cout << "For the entered application name:" << applicationNameArg.getValue() << " have been received "
                      << appCards.size() << " Cards." << std::endl;
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
