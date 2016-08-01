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

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <iterator>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>

#include <cli/pair.h>
#include <cli/version.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>
#include <cli/wrapper/sdk/CardClient.h>
#include <cli/wrapper/sdk/Card.h>
#include <cli/wrapper/sdk/PrivateKey.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace wsdk = cli::wrapper::sdk;

static void reset(std::istream& in);

int decrypt_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Decrypt *plain.txt.enc* for a user identified by his password:\n"
            "\tvirgil decrypt -i plain.txt.enc -o plain.txt -r password:strong_password\n\n"

            "2. Decrypt plain.txt.enc for Bob identified by his private key + `recipient-id` "
            "[id|vcard|email|private]:\n"
            "\tvirgil decrypt -i plain.txt.enc -o plain.txt -k bob/private.key -r id:<recipient_id>\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kDecrypt_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", cli::kDecrypt_Input_Description, false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", cli::kDecrypt_Output_Description, false, "", "file");

        TCLAP::ValueArg<std::string> contentInfoArg("c", "content-info", cli::kDecrypt_ContentInfo_Description, false,
                                                    "", "file");

        TCLAP::ValueArg<std::string> privateKeyArg(cli::kPrivateKey_ShortName, cli::kPrivateKey_LongName,
                                                   cli::kPrivateKey_Description, false, "", cli::kPrivateKey_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            cli::kPrivateKeyPassword_ShortName, cli::kPrivateKeyPassword_LongName, cli::kPrivateKeyPassword_Description,
            false, "", cli::kPrivateKeyPassword_TypeDesc);

        TCLAP::ValueArg<std::string> recipientArg("r", "recipient", cli::kDecrypt_Recipient_Description, true, "",
                                                  "arg");

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(recipientArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(contentInfoArg);
        cmd.add(outArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);

        auto recipientFormat = cli::parsePair(recipientArg.getValue());
        cli::checkFormatRecipientArg(recipientFormat);

        // Create cipher
        vcrypto::VirgilStreamCipher cipher;

        if (!contentInfoArg.getValue().empty()) {
            // Set content info.
            std::ifstream contentInfoFile(contentInfoArg.getValue(), std::ios::in | std::ios::binary);
            if (!contentInfoFile) {
                throw std::invalid_argument("cannot read file: " + contentInfoArg.getValue());
            }

            vcrypto::VirgilByteArray contentInfo((std::istreambuf_iterator<char>(contentInfoFile)),
                                                 std::istreambuf_iterator<char>());
            cipher.setContentInfo(contentInfo);
        }

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

        // Create IO streams
        vcrypto::stream::VirgilStreamDataSource dataSource(*inStream);
        vcrypto::stream::VirgilStreamDataSink dataSink(*outStream);

        std::string type = recipientFormat.first;
        std::string value = recipientFormat.second;

        if (type == "password") {
            vcrypto::VirgilByteArray password = virgil::crypto::str2bytes(value);
            cipher.decryptWithPassword(dataSource, dataSink, password);
            if (verboseArg.isSet()) {
                std::cout << "File has been decrypted with a password" << std::endl;
            }
        } else {
            // type = [id|vcard|email]
            // Read private key
            std::string pathToPrivateKeyFile = privateKeyArg.getValue();
            vcrypto::VirgilByteArray privateKey = wsdk::readPrivateKey(pathToPrivateKeyFile);

            vcrypto::VirgilByteArray privateKeyPassword;
            if (privateKeyPasswordArg.isSet()) {
                privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
            } else {
                privateKeyPassword = cli::setPrivateKeyPass(privateKey);
            }

            // type = [id|vcard|email|private]
            // if recipient email:<value>, then a download Virgil Card with confirmed identity
            if (type == "id") {
                std::string recipientCardId = value;
                cipher.decryptWithKey(dataSource, dataSink, vcrypto::str2bytes(recipientCardId), privateKey,
                                      privateKeyPassword);
                return EXIT_SUCCESS;
            }

            if (type == "vcard") {
                std::string pathVCardFile = value;
                auto card = wsdk::readCard(pathVCardFile);
                cipher.decryptWithKey(dataSource, dataSink, vcrypto::str2bytes(card.getId()), privateKey,
                                      privateKeyPassword);
                return EXIT_SUCCESS;
            }

            wsdk::CardClient cardClient;
            std::vector<vsdk::models::CardModel> cards;
            if (type == "private") {
                // private:<type>:<value>
                auto pairTypeAndValue = cli::parsePair(value);
                std::string type = pairTypeAndValue.first;
                std::string value = pairTypeAndValue.second;

                auto privateCards = cardClient.getConfirmedPrivateCards(value, type);
                cards.insert(cards.end(), privateCards.begin(), privateCards.end());
            }

            if (type == "email") {
                std::string email = value;
                auto globalCards = cardClient.getGlobalCards(email);
                cards.insert(cards.end(), globalCards.begin(), globalCards.end());
            }

            if (cards.empty()) {
                throw std::runtime_error(std::string("Cards by ") + type + ":" + value + " haven't been found.");
            }

            size_t countErrorDecryptWithKey = 0;
            vcrypto::VirgilByteArray encryptedData((std::istreambuf_iterator<char>(inStream->rdbuf())),
                                                   std::istreambuf_iterator<char>());

            for (const auto& card : cards) {
                try {
                    if (inArg.getValue().empty() || inArg.getValue() == "-") {
                        vcrypto::VirgilCipher cipher;
                        vcrypto::VirgilByteArray decryptedData = cipher.decryptWithKey(
                            encryptedData, vcrypto::str2bytes(card.getId()), privateKey, privateKeyPassword);

                        cli::writeBytes(outArg.getValue(), decryptedData);
                        break;
                    } else {
                        reset(*inStream);
                        vcrypto::VirgilStreamCipher streamCipher;
                        streamCipher.decryptWithKey(dataSource, dataSink, vcrypto::str2bytes(card.getId()), privateKey,
                                                    privateKeyPassword);
                        break;
                    }

                } catch (std::exception& exception) {
                    ++countErrorDecryptWithKey;
                    if (verboseArg.isSet()) {
                        std::cout << "decrypt. Warning: " << exception.what() << std::endl;
                    }
                }
            }

            if (countErrorDecryptWithKey == cards.size()) {
                throw std::runtime_error("File can’t be decrypted:\n"
                                         "wrong card-id or/and private key.\n");
            }

            if (verboseArg.isSet()) {
                std::cout << "File has been decrypted with a private key" << std::endl;
            }
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "decrypt. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "decrypt. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void reset(std::istream& in) {
    in.clear();
    in.seekg(0, in.beg);
}
