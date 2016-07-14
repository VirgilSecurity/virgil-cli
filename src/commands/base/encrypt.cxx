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
#include <cli/wrapper/sdk/CardClient.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace vcli = virgil::cli;
namespace wsdk = virgil_cli::wrapper::sdk;

static void checkFormatRecipientsArg(const std::vector<std::string>& recipientsData);

static void addKeyRecipient(const vsdk::models::CardModel& card, const std::string& arg,
                            vcrypto::VirgilStreamCipher& cipher, std::map<std::string, std::string>& recipientIdArgs);

int encrypt_main(int argc, char** argv) {
    try {
        std::string description = "The utility allows you to encrypt data with a password or combination "
                                  "of Public Key + recipient-id. recipient-id is an identifier which "
                                  "will be connected with the Public Key. If a sender has a Card, his "
                                  "recipient-id is the Card's id. Also, the Public Keys is saved in  "
                                  "the Card.\n\n";

        std::vector<std::string> examples;
        examples.push_back("Alice encrypts the data for Bob using his email (searching the Global Virgil Card(s)):\n"
                           "virgil encrypt -i plain.txt -o plain.txt.enc email:bob@domain.com\n\n");

        examples.push_back("Alice encrypts the data for Bob using his email (searching the Private Virgil Card(s)):\n"
                           "virgil encrypt -i plain.txt -o plain.txt.enc private:email:bob@domain.com\n\n");

        examples.push_back(
            "Alice encrypts the data for Bob and Tom using their emails:\n"
            "virgil encrypt -i plain.txt -o plain.txt.enc email:bob@domain.com email:tom@domain.com\n\n");

        examples.push_back("Alice encrypts the data with a password:\n"
                           "virgil encrypt -i plain.txt -o plain.txt.enc password:strong_password\n\n");

        examples.push_back("Alice encrypts the data with a combination of Public Key + recipient-id:\n"
                           "virgil encrypt -i plain.txt -o plain.txt.enc pubkey:bob/public.key:ForBob\n\n");

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
            "recipient",
            "Contains information about one recipient.\n"
            "Format:\n"
            "[password|id|vcard|email|pubkey|private]:<value>\n"
            "where:\n"
            "\t* if password, then <value> - recipient's password;\n"
            "\t* if id, then <value> - recipient's UUID associated with Virgil\n\t Card identifier;\n"
            "\t* if vcard, then <value> - recipient's the Virgil Card file\n\t  stored locally;\n"
            "\t* if email, then <value> - recipient's email;\n"
            "\t* if pubkey, then <value> - recipient's public key + identifier, for example:\n"
            " pubkey:bob/public.key:ForBob.\n"
            "\t* if private, then set type:value for searching Private Virgil Card(s)  with confirmed identity (see "
            "'card-create-private'). "
            " For example: private:<obfuscator_type>:<obfuscator_value>. ( obfiscator - see 'virgil hash')",
            false, "recipient", false);

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Shows detailed information.", false);

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
            auto recipientPair = vcli::parsePair(recipientArg);
            if (recipientPair.first == "password") {
                vcrypto::VirgilByteArray pwd = virgil::crypto::str2bytes(recipientPair.second);
                cipher.addPasswordRecipient(pwd);
            } else {
                // recipientsPair.first [pubkey | private | id | vcard | email]
                if (recipientPair.first == "pubkey") {
                    // pubkey:<path-pub-key>:<recipient-id>
                    // recipientPair.second == <path-pub-key>:<recipient-id>
                    auto pubkeyAndRecipientId = vcli::parsePair(recipientPair.second);
                    std::string pathPublicKeyFile = pubkeyAndRecipientId.first;

                    auto publicKeyBytes = vcli::readFileBytes(pathPublicKeyFile);
                    std::string recipientId = pubkeyAndRecipientId.second;
                    if (!cipher.keyRecipientExists(vcrypto::str2bytes(recipientId))) {
                        cipher.addKeyRecipient(vcrypto::str2bytes(recipientId), publicKeyBytes);
                        recipientIdArgs[recipientId] = recipientArg;
                    } else {
                        auto it = recipientIdArgs.find(recipientId);
                        if (it != recipientIdArgs.end()) {
                            std::string argContainsRecipientId;
                            std::string error = "recipient-id must be unique.\n";
                            error += "This recipient-id has already been used in this argument.";
                            error += it->second;
                            throw std::invalid_argument(error);
                        }
                    }

                } else {
                    wsdk::CardClient cardClient;
                    if (recipientPair.first == "private") {
                        auto typeAndValue = vcli::parsePair(recipientPair.second);
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
        auto recipientPair = vcli::parsePair(recipientData);
        if (recipientPair.first == "pubkey" || recipientPair.first == "private") {
            // pubkey:<path-pub-key>:<recipient-id>
            // private:<type>:<value> - for example: private:phone:<phone-number>
            // recipientPair.second == <path-pub-key>:<recipient-id> or <type>:<value>
            vcli::parsePair(recipientPair.second);
            continue;
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
            std::string argContainsRecipientId;
            std::string error = "recipient-id must be unique.\n";
            error += "This recipient-id has already been used in this argument.";
            error += it->second;
            throw std::invalid_argument(error);
        }
    }
}
