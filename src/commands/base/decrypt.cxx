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

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>

#include <cli/pair.h>
#include <cli/version.h>
#include <cli/util.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace vcli = virgil::cli;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN decrypt_main
#endif

static void checkFormatRecipientArg(const std::pair<std::string, std::string>& pairRecipientArg);

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Decrypt data with given password or given Private Key + Virgil Card.\n";

        std::vector<std::string> examples;
        examples.push_back("Decrypt data for user identified by password:\n"
                           "virgil decrypt -i plain.txt.enc -o plain.txt -r password:strong_password\n");

        examples.push_back(
            "Decrypt data for Bob identified by his Private Key + recipient-id [id|vcard|email|private]:\n"
            "virgil decrypt -i plain.txt.enc -o plain.txt -k bob/private.key -r id:<recipient_id>\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be decrypted. If omitted, stdin is used.", false, "",
                                           "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Decrypted data. If omitted, stdout is used.", false, "",
                                            "file");

        TCLAP::ValueArg<std::string> contentInfoArg("c", "content-info",
                                                    "Content info. Use this option if"
                                                    " content info is not embedded in the encrypted data.",
                                                    false, "", "file");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "key", "Private Key.", false, "", "file");

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            "p", "private-key-password", "Password to be used for Private Key encryption.", false, "", "arg");

        TCLAP::ValueArg<std::string> recipientArg(
            "r", "recipient", "Recipient defined in format:\n"
                              "[password|id|vcard|email|private]:<value>\n"
                              "where:\n"
                              "\t* if password, then <value> - recipient's password;\n"
                              "\t* if id, then <value> - recipient's UUID associated with Virgil Card identifier;\n"
                              "\t* if vcard, then <value> - recipient's Virgil Card/Cards file\n\t  stored locally;\n"
                              "\t* if email, then <value> - recipient's email;\n"
                              "\t* if private, then set type:value for searching Private Virgil Card[s].\n"
                              " For example: private:email:<obfuscator_email>. ( obfiscator - see 'virgil hash')\n",
            true, "", "arg");

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Show detailed information", false);

        cmd.add(verboseArg);
        cmd.add(recipientArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(contentInfoArg);
        cmd.add(outArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);

        auto recipientFormat = vcli::parsePair(recipientArg.getValue());
        vcli::checkFormatRecipientArg(recipientFormat);

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
            vcrypto::VirgilByteArray privateKey = vcli::readPrivateKey(pathToPrivateKeyFile);

            vcrypto::VirgilByteArray privateKeyPassword;
            if (privateKeyPasswordArg.isSet()) {
                privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
            } else {
                privateKeyPassword = vcli::setPrivateKeyPass(privateKey);
            }

            // type = [id|vcard|email|private]
            // if recipient email:<value>, then a download Virgil Card with confirmed identity
            if (type == "id") {
                std::string recipientCardId = value;
                cipher.decryptWithKey(dataSource, dataSink, vcrypto::str2bytes(recipientCardId), privateKey,
                                      privateKeyPassword);
                return EXIT_SUCCESS;
            }

            std::vector<std::string> recipientCardsId;
            if (type == "private") {
                // private:<type>:<value>
                auto pairTypeAndValue = vcli::parsePair(value);
                std::string type = pairTypeAndValue.first;
                std::string value = pairTypeAndValue.second;

                bool isSearchPrivateCard = true; // search the Private Virgil Card[s]
                recipientCardsId = vcli::getRecipientCardsId(verboseArg.isSet(), type, value, isSearchPrivateCard);
            } else {
                // type = [id|vcard|email]
                bool isSearchPrivateCard = false; // search the Global Virgil Card[s]
                recipientCardsId = vcli::getRecipientCardsId(verboseArg.isSet(), type, value, isSearchPrivateCard);
            }

            if (recipientCardsId.empty()) {
                if (verboseArg.isSet()) {
                    std::cout << "Cards by " << type << ":" << value << " haven't been found." << std::endl;
                    return EXIT_FAILURE;
                }
            }

            size_t countErrorDecryptWithKey = 0;
            for (const auto& recipientCardId : recipientCardsId) {
                try {
                    cipher.decryptWithKey(dataSource, dataSink, vcrypto::str2bytes(recipientCardId), privateKey,
                                          privateKeyPassword);
                } catch (std::exception& exception) {
                    ++countErrorDecryptWithKey;
                    if (verboseArg.isSet()) {
                        std::cout << "decrypt. Warning: " << exception.what() << std::endl;
                    }
                }
            }

            if (countErrorDecryptWithKey == recipientCardsId.size()) {
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

void checkFormatRecipientArg(const std::pair<std::string, std::string>& pairRecipientArg) {
    const std::string type = pairRecipientArg.first;
    if (type != "password" && type != "id" && type != "vcard" && type != "email") {
        throw std::invalid_argument("invalid type format: " + type + ". Expected format: '<key>:<value>'. "
                                                                     "Where <key> = [password|id|vcard|email]");
    }
}
