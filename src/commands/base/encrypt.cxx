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

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>

#include <virgil/sdk/keys/model/PublicKey.h>
#include <virgil/sdk/keys/model/UserDataType.h>
#include <virgil/sdk/keys/client/KeysClient.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilStreamCipher;
using virgil::crypto::stream::VirgilStreamDataSource;
using virgil::crypto::stream::VirgilStreamDataSink;

using virgil::sdk::keys::model::PublicKey;
using virgil::sdk::keys::model::UserDataType;
using virgil::sdk::keys::client::KeysClient;


/**
 * @brief Add recipients from the configuration files to the cipher.
 * @param configFiles - array of configuration files names.
 * @param cipher - recipients added to.
 * @return Number of added recipients.
 */
static size_t add_recipients_configs(const std::vector<std::string>& configFiles, VirgilStreamCipher* cipher);

/**
 * @brief Add recipients from the list to the cipher.
 * @param recipients - array of recipients <type:value>, where type can be [pass|vpk_file|email|phone|domain].
 * @param cipher - recipients added to.
 * @return Number of added recipients.
 */
static size_t add_recipients(const std::vector<std::string>& recipientsData, VirgilStreamCipher* cipher);

/**
 * @brief Add recipient to the cipher.
 * @param recipientData - <type:value>, where type can be [pass|key|email|phone|domain].
 * @param cipher - recipients added to.
 */
static void add_recipient(const std::string recipientIdType, const std::string recipientId,
        VirgilStreamCipher* cipher);


#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN encrypt_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Encrypt data", ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be encrypted. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Encrypted data. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> contentInfoArg("c", "content-info",
                "Content info. If omitted - becomes a part of the encrypted data.",
                false, "", "file");

        TCLAP::MultiArg<std::string> recipientsConfigArg("r", "recipients",
                "File that contains information about recipients. Each line "
                "can be either empty line, or comment line, or recipient defined in format:\n"
                "[pass|file|email|phone|domain]:<value>\n"
                "where:\n"
                "\t* if pass, then <value> - recipient's password;\n"
                "\t* if file, then <value> - recipient's Virgil Public Key file stored locally;\n"
                "\t* if email, then <value> - recipient's email;\n"
                "\t* if phone, then <value> - recipient's phone;\n"
                "\t* if domain, then <value> - recipient's domain.\n",
                false, "file");

        TCLAP::UnlabeledMultiArg<std::string> recipientsArg("recipient",
                "Contains information about one recipient. "
                "Same as significant line in the recipients configuration file.",
                false, "recipient", true);

        cmd.add(recipientsArg);
        cmd.add(recipientsConfigArg);
        cmd.add(contentInfoArg);
        cmd.add(outArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);

        // Create cipher
        VirgilStreamCipher cipher;

        // Add recipients
        size_t addedRecipientsCount = 0;
        addedRecipientsCount += add_recipients_configs(recipientsConfigArg.getValue(), &cipher);
        addedRecipientsCount += add_recipients(recipientsArg.getValue(), &cipher);
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
        if (outArg.getValue().empty() || outArg.getValue() == "-") {
            outStream = &std::cout;
        } else {
            outFile.open(outArg.getValue(), std::ios::out | std::ios::binary);
            if (!outFile) {
                throw std::invalid_argument("can not write file: " + outArg.getValue());
            }
            outStream = &outFile;
        }

        VirgilStreamDataSource dataSource(*inStream);
        VirgilStreamDataSink dataSink(*outStream);

        // Define whether embed content info or not
        bool embedContentInfo = contentInfoArg.getValue().empty();
        cipher.encrypt(dataSource, dataSink, embedContentInfo);

        // Write content info to file if it was not embedded
        if (!embedContentInfo) {
            std::ofstream contentInfoFile(contentInfoArg.getValue(), std::ios::out | std::ios::binary);
            if (!contentInfoFile) {
                throw std::invalid_argument("can not write file: " + contentInfoArg.getValue());
            }
            VirgilByteArray contentInfo = cipher.getContentInfo();
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

static size_t add_recipients_configs(const std::vector<std::string>& configFiles, VirgilStreamCipher* cipher) {
    size_t addedRecipientsCount = 0;
    for (const auto& configFile : configFiles) {
        std::ifstream file(configFile);
        if (!file) {
             throw std::invalid_argument("recipientsConfigArg: can not read recipient config file: " + configFile);
        }

        // Else
        std::string recipientData;
        unsigned long long numberLine = 0;
        while (file >> std::ws && std::getline(file, recipientData)) {
            ++numberLine;
            if (!recipientData.empty() && recipientData[0] != '#') {
                const auto recipientPair = virgil::cli::parse_pair(recipientData);
                const std::string recipientIdType = recipientPair.first;
                const std::string recipientId = recipientPair.second;
                try {
                    add_recipient(recipientIdType, recipientId, cipher);
                } catch (std::exception& exception) {
                    throw std::runtime_error("can not add recipient " + recipientIdType + ":" + recipientId +
                            " from line " + std::to_string(numberLine) + " . Details: " + exception.what());
                }
               ++addedRecipientsCount;
            }
        }
    }

    return addedRecipientsCount;
}

static size_t add_recipients(const std::vector<std::string>& recipientsData, VirgilStreamCipher* cipher) {
    size_t addedRecipientsCount = 0;
    for (const auto& recipientData : recipientsData) {
        const auto recipientPair = virgil::cli::parse_pair(recipientData);
        const std::string recipientIdType = recipientPair.first;
        const std::string recipientId = recipientPair.second;
        try {
            add_recipient(recipientIdType, recipientId, cipher);
        } catch (std::exception& exception) {
            throw std::invalid_argument("can not add recipient. Error " + recipientIdType +
                    ":" + recipientId + "\n" + exception.what());
        }
        ++addedRecipientsCount;
    }
    return addedRecipientsCount;
}

static void add_recipient(const std::string recipientIdType, const std::string recipientId,
        VirgilStreamCipher* cipher) {
    if (recipientIdType == "pass") {
        VirgilByteArray pwd = virgil::crypto::str2bytes(recipientId);
        cipher->addPasswordRecipient(pwd);
    } else {
        PublicKey publicKey;
        if (recipientIdType == "file") {
            // Read Virgil Public Key from file
            std::ifstream virgilPublicKeyFile(recipientId, std::ios::in | std::ios::binary);
            if (!virgilPublicKeyFile) {
                throw std::invalid_argument("can not read recipient's Virgil Public Key file: " + recipientId);
            }
            publicKey = virgil::cli::read_virgil_public_key(virgilPublicKeyFile);
        } else {
            // Get Virgil Public Key from the service
            publicKey = virgil::cli::get_virgil_public_key(recipientId);
        }
        VirgilByteArray publicKeyId = virgil::crypto::str2bytes(publicKey.publicKeyId());
        cipher->addKeyRecipient(publicKeyId, publicKey.key());
    }
}
