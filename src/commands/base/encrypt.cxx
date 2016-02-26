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

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>

#include <virgil/sdk/model/Card.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace vcli = virgil::cli;


static void checked(const std::vector<std::string>& recipientsData);


/**
 * @brief Add recipients from the list to the cipher.
 * @param recipients - array of recipients <type:value>, where type can be [pass|vpk_file|email|phone|domain].
 * @param cipher - recipients added to.
 * @return Number of added recipients.
 */
static size_t add_recipients(const std::vector<std::string>& recipientsData, const bool includeUnconrimedCard,
        vcrypto::VirgilStreamCipher* cipher);

/**
 * @brief Add recipient to the cipher.
 * @param recipientData - <type:value>, where type can be [pass|key|email|phone|domain].
 * @param cipher - recipients added to.
 */
static void add_recipient(const std::string& recipientType, const std::string& recipientValue,
        const bool includeUnconrimedCard, vcrypto::VirgilStreamCipher* cipher);


#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN encrypt_main
#endif

int MAIN(int argc, char **argv) {
    try {
        std::string description = "Encrypt data for given recipients. Recipient can be represented"
              " either by the password, or by the Virgil Public Key.\n";

        std::vector <std::string> examples;
        examples.push_back(
                "Encrypt data for Bob identified by email:\n"
                "virgil encrypt -i plain.txt -o plain.txt.enc email:bob@domain.com\n");

        examples.push_back(
                "Encrypt data for Bob and Tom identified by emails:\n"
                "virgil encrypt -i plain.txt -o plain.txt.enc email:bob@domain.com email:tom@domain.com\n");

        examples.push_back(
                "Encrypt data for user identified by password::\n"
                "virgil encrypt -i plain.txt -o plain.txt.enc pass:strong_password\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be encrypted. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Encrypted data. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> contentInfoArg("c", "content-info",
                "Content info - meta information about encrypted data. If omitted becomes a part of"
                " the encrypted data.", false, "", "file");

        TCLAP::ValueArg<bool> includeUnconfirmedArg("", "include_unconrimed", "Search Cards with unconfirm "
                "identity. Default false", false, "", "bool");

        TCLAP::UnlabeledMultiArg<std::string> recipientsArg("recipient",
                "Contains information about one recipient.\n"
                "Format:\n"
                "[pass|id|vcard|email]:<value>\n"
                "where:\n"
                "\t* if pass, then <value> - recipient's password;\n"
                "\t* if id, then <value> - recipient's Virgil Card identifier;\n"
                "\t* if vcard, then <value> - recipient's Virgil Card/Cards file\n\t  stored locally;\n"
                "\t* if email, then <value> - recipient's email;\n",
                false, "recipient", false);

        cmd.add(recipientsArg);
        cmd.add(includeUnconfirmedArg);
        cmd.add(contentInfoArg);
        cmd.add(outArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);

        checked(recipientsArg.getValue());

       // Create cipher
        vcrypto::VirgilStreamCipher cipher;

       // Add recipients
       size_t addedRecipientsCount = 0;
       addedRecipientsCount += add_recipients(recipientsArg.getValue(), includeUnconfirmedArg.getValue(), &cipher);
       if (addedRecipientsCount == 0) {
           throw std::invalid_argument("no recipients are defined");
       }

       // Prepare input
       std::istream* inStream;
       std::ifstream inFile;
       if (inArg.getValue().empty() || inArg.getValue() == "-") {
           inStream = &std::cin;
       } else {
           inFile.open(inArg.getValue(), std::ios::in | std::ios::binary);
           if (!inFile) {
               throw std::invalid_argument("can not read file: " + inArg.getValue());
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
               throw std::invalid_argument("can not write file: " + outArg.getValue());
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
               throw std::invalid_argument("can not write file: " + contentInfoArg.getValue());
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

void checked(const std::vector<std::string>& recipientsData) {
    for (const auto& recipientData : recipientsData) {
        auto recipientPair = vcli::parsePair(recipientData);
        vcli::checkFormatRecipientArg(recipientPair);
    }
}

size_t add_recipients(const std::vector<std::string>& recipientsData, const bool includeUnconrimedCard,
        vcrypto::VirgilStreamCipher* cipher) {
    size_t addedRecipientsCount = 0;
    for (const auto& recipientData : recipientsData) {
        auto recipientPair = vcli::parsePair(recipientData);
        std::string recipientType = recipientPair.first;
        std::string recipientValue = recipientPair.second;
        try {
            add_recipient(recipientType, recipientValue, includeUnconrimedCard, cipher);
        } catch (std::exception& exception) {
            throw std::invalid_argument("can not add recipient. Error " + recipientType +
                    ":" + recipientValue + "\n" + exception.what());
        }
        ++addedRecipientsCount;
    }
    return addedRecipientsCount;
}

void add_recipient(const std::string& recipientType, const std::string& recipientValue,
        const bool includeUnconrimedCard, vcrypto::VirgilStreamCipher* cipher) {
    if (recipientType == "pass") {
        vcrypto::VirgilByteArray pwd = virgil::crypto::str2bytes(recipientValue);
        cipher->addPasswordRecipient(pwd);
    } else {
        // Else recipientType [id|vcard|email]
        std::vector<vsdk::model::Card> recipientsCard = vcli::getRecipientCards(recipientType, recipientValue,
                includeUnconrimedCard);
        for (const auto& recipientCard : recipientsCard) {
            cipher->addKeyRecipient(
                    vcrypto::str2bytes(recipientCard.getId()),
                    recipientCard.getPublicKey().getKey()
            );
        }
    }
}
