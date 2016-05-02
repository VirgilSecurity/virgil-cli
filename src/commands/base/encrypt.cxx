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

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <set>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>

#include <virgil/sdk/models/CardModel.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace vcli = virgil::cli;

using PairStrStr = std::pair<std::string, std::string>;
using PairPubKey_RecipientId = std::pair<vcrypto::VirgilByteArray, std::string>;

static std::vector<PairStrStr> checkFormatRecipientsArg(const std::vector<std::string>& recipientsData);

static void checkUniqueRecipientsPairs(const std::vector<PairStrStr>& recipientsPairs);

static std::vector<PairStrStr> checkRecipientsArgs(const std::vector<std::string>& recipientsData);

static void checkUniqueRecipientsId(const std::vector<PairPubKey_RecipientId>& pairs,
                                    const std::vector<vsdk::models::CardModel>& cards);

static void addPasswordsRecipients(const bool verbose, const std::vector<std::string>& recipientsPasswords,
                                   vcrypto::VirgilStreamCipher* cipher);

static void addKeysRecipients(const bool verbose, const std::vector<PairPubKey_RecipientId>& pairs,
                              const std::vector<vsdk::models::CardModel>& cards, vcrypto::VirgilStreamCipher* cipher);

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN encrypt_main
#endif

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Encrypt data for given recipients. Recipient can be represented"
                                  " either by the password, or by the Virgil Card Key.\n";

        std::vector<std::string> examples;
        examples.push_back("Alice encrypts the data for Bob using his email:\n"
                           "virgil encrypt -i plain.txt -o plain.txt.enc email:bob@domain.com\n");

        examples.push_back("Alice encrypts the data for Bob and Tom using their emails:\n"
                           "virgil encrypt -i plain.txt -o plain.txt.enc email:bob@domain.com email:tom@domain.com\n");

        examples.push_back("Alice encrypts the data with a password:\n"
                           "virgil encrypt -i plain.txt -o plain.txt.enc password:strong_password\n");

        examples.push_back("Alice encrypts the data with a combination of Public Key + recipient-id."
                           "You will be asked to enter recipient-id:\n"
                           "virgil encrypt -i plain.txt -o plain.txt.enc pubkey:public.key:ForBob\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be encrypted. If omitted, stdin is used.", false, "",
                                           "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Encrypted data. If omitted, stdout is used.", false, "",
                                            "file");

        TCLAP::ValueArg<std::string> contentInfoArg(
            "c", "content-info", "Content info - meta information about encrypted data. If omitted, becomes a part of"
                                 " the encrypted data.",
            false, "", "file");

        TCLAP::UnlabeledMultiArg<std::string> recipientsArg(
            "recipient", "Contains information about one recipient.\n"
                         "Format:\n"
                         "[password|id|vcard|email|pubkey]:<value>\n"
                         "where:\n"
                         "\t* if password, then <value> - recipient's password;\n"
                         "\t* if id, then <value> - recipient's UUID associated with Virgil\n\t Card identifier;\n"
                         "\t* if vcard, then <value> - recipient's the Virgil Card file\n\t  stored locally;\n"
                         "\t* if email, then <value> - recipient's email;\n"
                         "\t* if pubkey, then <value> - recipient's Public Key + identifier, for example:\n"
                         " pubkey:bob/public.key:ForBob.\n",
            false, "recipient", false);

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Show detailed information", false);

        cmd.add(verboseArg);
        cmd.add(recipientsArg);
        cmd.add(contentInfoArg);
        cmd.add(outArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);

        auto recipientsPairs = checkRecipientsArgs(recipientsArg.getValue());
        std::vector<std::string> recipientsPasswords;
        std::vector<PairPubKey_RecipientId> pubKey_recipientId;
        std::vector<vsdk::models::CardModel> recipientCards;
        for (const auto recipientsPair : recipientsPairs) {
            if (recipientsPair.first == "password") {
                recipientsPasswords.push_back(recipientsPair.second);
            } else {
                // recipientsPair.first [id | vcard | email | pubkey]
                if (recipientsPair.first == "pubkey") {
                    //  public.key:<recipient-id>
                    auto pubkeyRecipientId = vcli::parsePair(recipientsPair.second);
                    std::string pathToPublicKeyFile = pubkeyRecipientId.first;
                    auto publicKey = vcli::readFileBytes(pathToPublicKeyFile);
                    std::string recipientId = pubkeyRecipientId.second;
                    pubKey_recipientId.push_back(std::make_pair(publicKey, pubkeyRecipientId.second));
                } else {
                    // Else recipientsPair.first [id | vcard | email]
                    // if recipient email:<value>, then download a Virgil Card with confirmed identity
                    bool includeUnconrimedCard = false;
                    recipientCards = vcli::getRecipientCards(verboseArg.isSet(), recipientsPair.first,
                                                             recipientsPair.second, includeUnconrimedCard);
                }
            }
        }

        std::cout << "recipientCards.empty() " << recipientCards.empty() << std::endl;

        if (recipientsPasswords.empty() && pubKey_recipientId.empty() && recipientCards.empty()) {
            throw std::invalid_argument("no recipients are defined");
        }

        if (!pubKey_recipientId.empty()) {
            checkUniqueRecipientsId(pubKey_recipientId, recipientCards);
        }

        // Create cipher
        vcrypto::VirgilStreamCipher cipher;
        addPasswordsRecipients(verboseArg.isSet(), recipientsPasswords, &cipher);
        addKeysRecipients(verboseArg.isSet(), pubKey_recipientId, recipientCards, &cipher);

        // Prepare input
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

/*

1. Проверяем разбитие по двоеточию
2. Проверяем на уникальность всех переданных данных
3. Проверяем уникальность всех переданных recipient-id.
Для этого берем id с vcard, из выкаченных Карт по email, id.
*/

std::vector<PairStrStr> checkFormatRecipientsArg(const std::vector<std::string>& recipientsData) {
    std::vector<PairStrStr> recipientsPairs;
    for (const auto& recipientData : recipientsData) {
        auto recipientPair = vcli::parsePair(recipientData);
        vcli::checkFormatRecipientArg(recipientPair);
        if (recipientPair.first == "pubkey") {
            auto pubkeyRecipientId = vcli::parsePair(recipientPair.second);
        }
        recipientsPairs.push_back(recipientPair);
    }
    return recipientsPairs;
}

void checkUniqueRecipientsPairs(const std::vector<PairStrStr>& recipientsPairs) {
    std::set<PairStrStr> uniqueRecipientsPairs;
    for (const auto& recipientPair : recipientsPairs) {
        if (uniqueRecipientsPairs.count(recipientPair) == 0) {
            uniqueRecipientsPairs.insert(recipientPair);
        } else {
            std::string error = "recipient must be unique. this recipient ";
            error += recipientPair.first + ":" + recipientPair.second + " has already.";
            throw std::logic_error(error);
        }
    }
}

std::vector<PairStrStr> checkRecipientsArgs(const std::vector<std::string>& recipientsData) {
    auto recipientsPairs = checkFormatRecipientsArg(recipientsData);
    checkUniqueRecipientsPairs(recipientsPairs);
    return recipientsPairs;
}

void checkUniqueRecipientsId(const std::vector<PairPubKey_RecipientId>& pairs,
                             const std::vector<vsdk::models::CardModel>& cards) {
    // pubkey:bob/public.key:ForBob   pubkey:<path_public_key>:<recipient_id>
    std::vector<std::string> recipientsId_PubKeyArgs;
    for (const auto& pair : pairs) {
        recipientsId_PubKeyArgs.push_back(pair.second);
    }

    std::set<std::string> uniqueRecipientsId;
    for (const auto& recipientId : recipientsId_PubKeyArgs) {
        if (uniqueRecipientsId.count(recipientId) == 0) {
            uniqueRecipientsId.insert(recipientId);
        } else {
            std::string error = "recipient id must be unique. this recipient id ";
            error += recipientId + " has already.";
            throw std::logic_error(error);
        }
    }

    if (!cards.empty()) {
        for (const auto& card : cards) {
            if (uniqueRecipientsId.count(card.getId()) == 0) {
                uniqueRecipientsId.insert(card.getId());
            } else {
                auto identity = card.getCardIdentity();
                std::string error = "recipient id must be unique. this recipient id ";
                error +=
                    card.getId() + " which refers on the card with identity " + identity.getValue() + " has already.";
                throw std::logic_error(error);
            }
        }
    }
}

void addPasswordsRecipients(const bool verbose, const std::vector<std::string>& recipientsPasswords,
                            vcrypto::VirgilStreamCipher* cipher) {
    for (const auto& recipientPassword : recipientsPasswords) {
        vcrypto::VirgilByteArray pwd = virgil::crypto::str2bytes(recipientPassword);
        if (!pwd.empty()) {
            cipher->addPasswordRecipient(pwd);
            if (verbose) {
                std::cout << "File has been password encrypted" << std::endl;
            }
        }
    }
}

void addKeysRecipients(const bool verbose, const std::vector<PairPubKey_RecipientId>& pairs,
                       const std::vector<vsdk::models::CardModel>& cards, vcrypto::VirgilStreamCipher* cipher) {
    for (const auto& pair : pairs) {
        auto publicKey = pair.first;
        auto recipientId = vcrypto::str2bytes(pair.second);
        if (!recipientId.empty() && !publicKey.empty()) {
            cipher->addKeyRecipient(recipientId, publicKey);
        }
        if (verbose) {
            std::cout << "File has been recipient-id:" << pair.second << "  and public key encrypted" << std::endl;
        }
    }

    for (const auto& card : cards) {
        cipher->addKeyRecipient(vcrypto::str2bytes(card.getId()), card.getPublicKey().getKey());
        if (verbose) {
            std::cout << "File has been card-id:" << card.getId() << ", identity:" << card.getCardIdentity().getValue()
                      << "  and card public key encrypted" << std::endl;
        }
    }
}

