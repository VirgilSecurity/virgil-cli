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
#include <vector>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>

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
#define MAIN card_search_private_main
#endif

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Search for the Private Virgil Card[s] from the Virgil Keys Service\n";

        std::vector<std::string> examples;
        examples.push_back("Search for the Private Virgil Card[s] with a confirmed Identity:\n"
                           "virgil card-search-private -d alice@gmail.com -t email -o alice/\n\n");

        examples.push_back(
            "Search for Private Virgil Card with a confirmed Identity and an unconfirmaed Identity:\n"
            "virgil card-search-private -d alice@gmail.com -t email -o alice-with-unconfirmed-identity/ -u\n\n");

        examples.push_back("Search for the Private Virgil Card[s] with a confirmed Identity:\n"
                           "virgil card-search-private -d <obfuscated_value> -t <obfuscated_type> -o alice/\n\n");

        examples.push_back("Search for Private Virgil Card with a confirmed Identity and an unconfirmaed Identity:\n"
                           "virgil card-search-private -d <obfuscated_value> -t <obfuscated_type> -o "
                           "alice-with-unconfirmed-identity/ -u\n\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Folder in which will be saved a Virgil Cards", false, "",
                                            "arg");

        TCLAP::ValueArg<std::string> identityArg(
            "d", "identity", "Identity value or obfuscated identity value (see 'virgil hash')", true, "", "arg");

        TCLAP::ValueArg<std::string> identityTypeArg(
            "t", "identity-type", "Identity type or obfuscated identity type (see 'virgil hash')", true, "", "arg");

        TCLAP::SwitchArg unconfirmedArg("u", "unconfirmed", "Search Cards include unconfirmed identity", false);

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Show detailed information", false);

        cmd.add(verboseArg);
        cmd.add(unconfirmedArg);
        cmd.add(identityTypeArg);
        cmd.add(identityArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        bool includeUnconfirmed = unconfirmedArg.getValue();
        vcli::ConfigFile configFile = vcli::readConfigFile(verboseArg.isSet());
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.serviceUri);
        std::vector<vsdk::models::CardModel> foundCards;
        foundCards = servicesHub.card().search(identityArg.getValue(), identityTypeArg.getValue(), includeUnconfirmed);

        if (foundCards.empty()) {
            if (verboseArg.isSet()) {
                std::cout << "Cards by type:" << identityTypeArg.getValue() << "; value:" << identityArg.getValue()
                          << " haven't been found." << std::endl;
            }
            return EXIT_FAILURE;
        }

        size_t countCardUnconfirmedIdentity = 0;
        for (auto&& foundCard : foundCards) {
            if (foundCard.authorizedBy().empty()) {
                ++countCardUnconfirmedIdentity;
            }
        }

        std::string pathTofolder = outArg.getValue();
        if (pathTofolder.empty()) {
            for (auto&& foundCard : foundCards) {
                std::string foundCardStr = vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(foundCard);
                vcli::writeBytes(pathTofolder, foundCardStr);
            }
        } else {
            for (auto&& foundCard : foundCards) {
                std::string identity = foundCard.getCardIdentity().getValue();
                std::string cardId = foundCard.getId();
                std::string isConfirmed;
                if (!foundCard.authorizedBy().empty()) {
                    isConfirmed = "confirmed";
                } else {
                    isConfirmed = "unconfirmed";
                }

                std::string fileName = identity + "-" + isConfirmed + "-id-" + foundCard.getId() + ".vcard";
                std::string foundCardStr = vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(foundCard);
                vcli::writeBytes(pathTofolder + "/" + fileName, foundCardStr);
            }
        }

        if (includeUnconfirmed) {
            if (verboseArg.isSet()) {
                std::cout << "For the entered value:" << identityArg.getValue() << " have been received "
                          << countCardUnconfirmedIdentity << " Cards with unconfirmed Identity and "
                          << foundCards.size() - countCardUnconfirmedIdentity << "  with confirmed Identity."
                          << std::endl;
            }
        } else {
            if (verboseArg.isSet()) {
                std::cout << "For the entered value:" << identityArg.getValue() << " have been received "
                          << foundCards.size() - countCardUnconfirmedIdentity << " with confirmed Identity."
                          << std::endl;
            }
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "card-search. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "card-search. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
