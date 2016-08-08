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
#include <cli/wrapper/sdk/PrivateKey.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;
namespace wsdk = cli::wrapper::sdk;

static void writeCard(const std::string& pathTofolder, const vsdk::models::CardModel& card);

int card_get_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Receive a private/global Virgil Card by card-id:\n"
            "\tvirgil card-get -a <card-id> -o cards/\n\n",

            "2. Return a group of private/global Cards connected with public-key-id, card-id belongs to "
            "one of the Cards:\n"
            "\tvirgil card-get -a <card-id> -e <public-key-id> -k alice/private.key -o cards/\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kCardGet_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", cli::kCardGet_Output_Description, false, "", "arg");

        TCLAP::ValueArg<std::string> cardIdArg(cli::kCardId_ShortName, cli::kCardId_LongName, cli::kCardId_Description,
                                               true, "", cli::kCardId_TypeDesc);

        TCLAP::ValueArg<std::string> publicKeyIdArg(cli::kPublicKeyId_ShortName, cli::kPublicKeyId_LongName,
                                                    cli::kPublicKeyId_Description, false, "",
                                                    cli::kPublicKeyId_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyArg(cli::kPrivateKey_ShortName, cli::kPrivateKey_LongName,
                                                   cli::kPrivateKey_Description, false, "", cli::kPrivateKey_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            cli::kPrivateKeyPassword_ShortName, cli::kPrivateKeyPassword_LongName, cli::kPrivateKeyPassword_Description,
            false, "", cli::kPrivateKeyPassword_TypeDesc);

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(publicKeyIdArg);
        cmd.add(cardIdArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        cli::ConfigFile configFile = cli::readConfigFile();
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.getServiceUri());
        std::string pathTofolder = outArg.getValue();

        if (publicKeyIdArg.isSet() && privateKeyArg.isSet()) {
            std::string pathPrivateKey = privateKeyArg.getValue();
            vcrypto::VirgilByteArray privateKey = wsdk::readPrivateKey(pathPrivateKey);
            vcrypto::VirgilByteArray privateKeyPassword;
            if (privateKeyPasswordArg.isSet()) {
                privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
            } else {
                privateKeyPassword = cli::setPrivateKeyPass(privateKey);
            }
            vsdk::Credentials credentials(privateKey, privateKeyPassword);

            std::vector<vsdk::models::CardModel> foundCards =
                servicesHub.card().get(publicKeyIdArg.getValue(), cardIdArg.getValue(), credentials);

            if (foundCards.empty()) {
                if (verboseArg.isSet()) {
                    std::cout << "Cards by card-id: " << cardIdArg.getValue()
                              << " and public-key-id: " << publicKeyIdArg.getValue() << " haven't been found."
                              << std::endl;
                }
                return EXIT_SUCCESS;
            }

            for (auto&& foundCard : foundCards) {
                writeCard(pathTofolder, foundCard);
            }

        } else {
            vsdk::models::CardModel foundCard = servicesHub.card().get(cardIdArg.getValue());
            writeCard(pathTofolder, foundCard);
            if (verboseArg.isSet()) {
                std::cout << "A Card with card-id:" << cardIdArg.getValue() << " has been received" << std::endl;
            }
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "card-get. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "card-get. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static void writeCard(const std::string& pathTofolder, const vsdk::models::CardModel& card) {
    std::string cardStr = vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(card);
    if (pathTofolder.empty()) {
        cli::writeBytes(pathTofolder, cardStr);
        return;
    }

    std::string identity = card.getCardIdentity().getValue();
    std::string fileName = identity + "-id-" + card.getId() + ".vcard";
    cli::writeBytes(pathTofolder + "/" + fileName, cardStr);
}
