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
#include <stdexcept>
#include <string>
#include <vector>
#include <map>
#include <fstream>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>
#include <cli/wrapper/sdk/CardClient.h>
#include <cli/wrapper/sdk/Card.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;

namespace wsdk = cli::wrapper::sdk;

static void checkFormatRecipientsArg(const std::vector<std::string>& recipientsData);

static void addKeyRecipient(const vsdk::models::CardModel& card, const std::string& arg,
                            vcrypto::VirgilStreamCipher& cipher, std::map<std::string, std::string>& recipientIdArgs);

int encrypt_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Alice encrypts the data for Bob using his email(searching the Global Virgil Card(s)):\n"
            "\tvirgil encrypt -i plain.txt -o plain.txt.enc email:bob@domain.com\n\n"

            "2. Alice encrypts the data for Bob using his email(searching the Private Virgil Card(s)):\n"
            "\tvirgil encrypt -i plain.txt -o plain.txt.enc private:email:bob@domain.com\n\n"

            "3. Alice encrypts the data for Bob and Tom using their emails:\n"
            "\tvirgil encrypt -i plain.txt -o plain.txt.enc email:bob@domain.com email:tom@domain.com\n\n"

            "4. Alice encrypts the data with a password:\n"
            "\tvirgil encrypt -i plain.txt -o plain.txt.enc password:strong_password\n\n"

            "5. Alice encrypts the data with a combination of Public Key + recipient-id:\n"
            "\tvirgil encrypt -i plain.txt -o plain.txt.enc pubkey:bob/public.key:ForBob\n\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kEncrypt_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        TCLAP::ValueArg<std::string> inArg("i", "in", cli::kEncrypt_Input_Description, false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", cli::kEncrypt_Output_Description, false, "", "file");

        TCLAP::ValueArg<std::string> contentInfoArg("c", "content-info", cli::kEncrypt_ContentInfo_Description, false,
                                                    "", "file");

        TCLAP::UnlabeledMultiArg<std::string> recipientsArg("recipient", cli::kEncrypt_UnlabeledRecipient_Description,
                                                            false, "recipient", false);

        cmd.add(verboseArg);
        cmd.add(recipientsArg);
        cmd.add(contentInfoArg);
        cmd.add(outArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);

        checkFormatRecipientsArg(recipientsArg.getValue());

        vcrypto::VirgilStreamCipher cipher;
        std::map<std::string, std::string> recipientIdArgs;
        for (const auto& recipientArg : recipientsArg.getValue()) {
            auto recipientPair = cli::parsePair(recipientArg);
            if (recipientPair.first == "password") {
                vcrypto::VirgilByteArray pwd = virgil::crypto::str2bytes(recipientPair.second);
                cipher.addPasswordRecipient(pwd);
            } else {
                // recipientsPair.first [pubkey | private | id | vcard | email]
                if (recipientPair.first == "pubkey") {
                    // pubkey:<path-pub-key>:<recipient-id>
                    // recipientPair.second == <path-pub-key>:<recipient-id>
                    auto pubkeyAndRecipientId = cli::parsePair(recipientPair.second);
                    std::string pathPublicKeyFile = pubkeyAndRecipientId.first;

                    auto publicKeyBytes = cli::readFileBytes(pathPublicKeyFile);
                    std::string recipientId = pubkeyAndRecipientId.second;
                    if (!cipher.keyRecipientExists(vcrypto::str2bytes(recipientId))) {
                        cipher.addKeyRecipient(vcrypto::str2bytes(recipientId), publicKeyBytes);
                        recipientIdArgs[recipientId] = recipientArg;
                    } else {
                        auto it = recipientIdArgs.find(recipientId);
                        if (it != recipientIdArgs.end()) {
                            std::string error = "recipient-id must be unique.\n";
                            error += "This recipient-id has already been used in this argument:\n";
                            error += it->second + ".";
                            throw std::invalid_argument(error);
                        }
                    }

                } else {
                    wsdk::CardClient cardClient;
                    if (recipientPair.first == "private") {
                        auto typeAndValue = cli::parsePair(recipientPair.second);
                        std::string type = typeAndValue.first;
                        std::string value = typeAndValue.second;
                        auto privateCards = cardClient.getConfirmedPrivateCards(type, value);
                        for (const auto& privateCard : privateCards) {
                            addKeyRecipient(privateCard, recipientArg, cipher, recipientIdArgs);
                        }
                    }

                    if (recipientPair.first == "id") {
                        std::string id = recipientPair.second;
                        auto card = cardClient.getCardById(id);
                        addKeyRecipient(card, recipientArg, cipher, recipientIdArgs);
                    }

                    if (recipientPair.first == "vcard") {
                        std::string pathVCard = recipientPair.second;
                        auto card = wsdk::readCard(pathVCard);
                        addKeyRecipient(card, recipientArg, cipher, recipientIdArgs);
                    }

                    if (recipientPair.first == "email") {
                        std::string email = recipientPair.second;
                        auto globalCards = cardClient.getGlobalCards(email);
                        for (const auto& globalCard : globalCards) {
                            addKeyRecipient(globalCard, recipientArg, cipher, recipientIdArgs);
                        }
                    }
                }
            }
        }

        std::istream* inStream;
        std::ifstream inFile;
        if (inArg.getValue().empty() || inArg.getValue() == "-") {
            inStream = &std::cin;
        } else {
            inFile.open(inArg.getValue(), std::ios::in | std::ios::binary);
            if (!inFile) {
                throw std::invalid_argument("cannot read file: " + inArg.getValue());
            }
            inStream = &inFile;
        }

        // Prepare output
        std::ostream* outStream;
        std::ofstream outFile;
        if (outArg.getValue().empty()) {
            outStream = &std::cout;
        } else {
            outFile.open(outArg.getValue(), std::ios::out | std::ios::binary);
            if (!outFile) {
                throw std::invalid_argument("cannot write file: " + outArg.getValue());
            }
            outStream = &outFile;
        }

        vcrypto::stream::VirgilStreamDataSource dataSource(*inStream);
        vcrypto::stream::VirgilStreamDataSink dataSink(*outStream);

        // Define whether embed content info or not
        bool embedContentInfo = contentInfoArg.getValue().empty();
        cipher.encrypt(dataSource, dataSink, embedContentInfo);

        // Write content info to file if it was not embedded
        if (!embedContentInfo) {
            std::ofstream contentInfoFile(contentInfoArg.getValue(), std::ios::out | std::ios::binary);
            if (!contentInfoFile) {
                throw std::invalid_argument("cannot write file: " + contentInfoArg.getValue());
            }
            vcrypto::VirgilByteArray contentInfo = cipher.getContentInfo();
            std::copy(contentInfo.begin(), contentInfo.end(), std::ostreambuf_iterator<char>(contentInfoFile));
        }
    } catch (TCLAP::ArgException& exception) {
        std::cerr << "encrypt. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "encrypt. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void checkFormatRecipientsArg(const std::vector<std::string>& recipientsData) {
    for (const auto& recipientData : recipientsData) {
        auto recipientPair = cli::parsePair(recipientData);
        if (recipientPair.first == "pubkey" || recipientPair.first == "private") {
            // pubkey:<path-pub-key>:<recipient-id>
            // private:<type>:<value> - for example: private:phone:<phone-number>
            // recipientPair.second == <path-pub-key>:<recipient-id> or <type>:<value>
            cli::parsePair(recipientPair.second);
        }
    }
}

void addKeyRecipient(const vsdk::models::CardModel& card, const std::string& arg, vcrypto::VirgilStreamCipher& cipher,
                     std::map<std::string, std::string>& recipientIdArgs) {
    auto publicKeyBytes = card.getPublicKey().getKey();
    std::string recipientId = card.getId();
    if (!cipher.keyRecipientExists(vcrypto::str2bytes(recipientId))) {
        cipher.addKeyRecipient(vcrypto::str2bytes(recipientId), publicKeyBytes);
        recipientIdArgs[recipientId] = arg;
    } else {
        auto it = recipientIdArgs.find(recipientId);
        if (it != recipientIdArgs.end()) {
            std::string error = "recipient-id must be unique.\n";
            error += "This recipient-id has already been used in this argument:\n";
            error += it->second + ".";
            throw std::invalid_argument(error);
        }
    }
}
