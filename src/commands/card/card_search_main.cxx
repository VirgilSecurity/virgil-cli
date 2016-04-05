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
#define MAIN card_search_main
#endif

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Search for a Virgil Card from the Virgil Keys service\n";

        std::vector<std::string> examples;
        examples.push_back("Search for Virgil Cards with a confirmed Identity:\n"
                           "virgil card-search -d email:alice@gmail.com -o alice/\n");

        examples.push_back("Search for Cards with a confirmed Identity and uncorfirmaed Identity:\n"
                           "virgil card-search -d email:alice@gmail.com -u alice-with-unconfirmed-identity/\n");

        examples.push_back("Search for Cards with an email, which have signed `card-sign' the"
                           " Cards with card-id:\n"
                           "virgil card-search -d email:alice@gmail.com "
                           "<user1_card_id> <user1_card_id>\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Folder in which will be saved a Virgil Cards", false, "",
                                            "arg");

        TCLAP::ValueArg<std::string> identityArg("d", "identity", "Identity: email", true, "", "arg");

        TCLAP::SwitchArg unconfirmedArg("u", "unconfirmed", "Search Cards include unconfirmed identity", false);

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Show detailed information", false);

        TCLAP::UnlabeledMultiArg<std::string> signedCardsIdArg("signed-card-id", "Signed card id", false, "card-id",
                                                               false);

        cmd.add(signedCardsIdArg);
        cmd.add(verboseArg);
        cmd.add(unconfirmedArg);
        cmd.add(identityArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        auto identityPair = vcli::parsePair(identityArg.getValue());
        std::string recipientType = identityPair.first;
        std::string recipientValue = identityPair.second;
        std::string arg = "-d, --identity";
        vcli::checkFormatIdentity(arg, recipientType);

        vsdk::models::IdentityModel::Type identityType = vsdk::models::fromString(recipientType);
        vsdk::dto::Identity identity(recipientValue, identityType);

        bool includeUnconfirmed = unconfirmedArg.getValue();

        vsdk::ServicesHub servicesHub(VIRGIL_ACCESS_TOKEN, vcli::readConfigFile());
        std::vector<vsdk::models::CardModel> foundCards;
        if (signedCardsIdArg.isSet()) {
            std::vector<std::string> signedCardsId = signedCardsIdArg.getValue();
            foundCards = servicesHub.card().search(identity, includeUnconfirmed, signedCardsId);
        } else {
            foundCards = servicesHub.card().search(identity, includeUnconfirmed);
        }

        if (foundCards.empty()) {
            if (verboseArg.isSet()) {
                std::cout << "Cards by email: " << recipientValue << " haven't been found." << std::endl;
            }
            return EXIT_FAILURE;
        }

        size_t countCardUnconfirmedIdentity = 0;
        for (auto&& foundCard : foundCards) {
            if (!foundCard.isConfirmed()) {
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
                if (foundCard.isConfirmed()) {
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
                std::cout << "For the entered email:" << recipientValue << " have been received "
                          << countCardUnconfirmedIdentity << " Cards with unconfirmed Identity and "
                          << foundCards.size() - countCardUnconfirmedIdentity << "  with confirmed Identity."
                          << std::endl;
            }
        } else {
            if (verboseArg.isSet()) {
                std::cout << "For the entered email:" << recipientValue << " have been received "
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
