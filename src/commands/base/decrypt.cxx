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

int MAIN(int argc, char **argv) {
    try {
        std::string description = "Decrypt data with given password or given Private Key.\n";

        std::vector <std::string> examples;
        examples.push_back(
                "Decrypt data for user identified by password:\n"
                "virgil decrypt -i plain.txt.enc -o plain.txt -k private.key -r pass:strong_password\n");

        examples.push_back(
                "Decrypt data for Bob identified by his key [id|vkey|email]:\n"
                "virgil decrypt -i plain.txt.enc -o plain.txt -k private.key -r email:bob@domain.com\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be decrypted. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Decrypted data. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> contentInfoArg("c", "content-info", "Content info. Use this option if"
                " content info is not embedded in the encrypted data.",
                false, "", "file");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "key", "Recipient's Private Ksey.",
                false, "", "file");

        TCLAP::ValueArg<std::string> privatePasswordArg("p", "key-pwd", "Recipient's Private Key"
                " password (max length 31 ASCII characters).", false, "", "arg");

        TCLAP::ValueArg<std::string> recipientArg("r", "recipient",
                "Recipient defined in format:\n"
                "[pass|id|vcard|email]:<value>\n"
                "where:\n"
                "if `pass`, then <value> - recipient's password (max length 31 ASCII characters);\n"
                "if `id`, then <value> - UUID associated with Virgil Card identifier;\n"
                "if `vcard`, then <value> - user's Virgil Card file stored locally;\n"
                "if `email`, then <value> - user email associated with Public Key.",
                true, "", "arg");

        cmd.add(recipientArg);
        cmd.add(privatePasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(contentInfoArg);
        cmd.add(outArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);


        auto recipientFormat = vcli::parsePair(recipientArg.getValue());
        vcli::checkFormatRecipientArg(recipientFormat);

        // Create cipher
        vcrypto::VirgilStreamCipher cipher;

        if(!contentInfoArg.getValue().empty()) {
            // Set content info.
            std::ifstream contentInfoFile(contentInfoArg.getValue(), std::ios::in | std::ios::binary);
            if (!contentInfoFile) {
                throw std::invalid_argument("can not read file: " + contentInfoArg.getValue());
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

        // Create IO streams
        vcrypto::stream::VirgilStreamDataSource dataSource(*inStream);
        vcrypto::stream::VirgilStreamDataSink dataSink(*outStream);

        std::string type = recipientFormat.first;
        std::string value = recipientFormat.second;

        if (type == "pass") {
            vcrypto::VirgilByteArray pass = virgil::crypto::str2bytes(value);
            cipher.decryptWithPassword(dataSource, dataSink, pass);
        } else  {
            // Read private key
            std::string pathToPrivateKeyFile = privateKeyArg.getValue();
            vcrypto::VirgilByteArray privateKey = vcli::readFileBytes(pathToPrivateKeyFile);
            vcrypto::VirgilByteArray privateKeyPassword = vcrypto::str2bytes(privatePasswordArg.getValue());

            // type = [id|vcard|email]
            std::vector<std::string> recipientCardsId = vcli::getRecipientCardsId(type, value);
            for(const auto& recipientCardId : recipientCardsId) {
                cipher.decryptWithKey(dataSource, dataSink, vcrypto::str2bytes(recipientCardId), privateKey,
                        privateKeyPassword);
            }
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
