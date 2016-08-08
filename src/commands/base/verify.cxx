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

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamSigner.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>
#include <cli/wrapper/sdk/PrivateKey.h>
#include <cli/wrapper/sdk/PublicKey.h>
#include <cli/wrapper/sdk/CardClient.h>
#include <cli/wrapper/sdk/Card.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace wsdk = cli::wrapper::sdk;

static void checkFormatRecipientArg(const std::pair<std::string, std::string>& pairRecipientArg);

int verify_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Bob verifies 'plain.txt.sign' with vcard:\n"
            "\tvirgil verify -i plain.txt -s plain.txt.sign -r vcard:bob/bob.vcard\n\n",

            "2. Bob verifies 'plain.txt.sign' with public key:\n"
            "\tvirgil verify -i plain.txt -s plain.txt.sign -r pubkey:bob/public.key\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kVerify_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", cli::kVerify_Input_Description, false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", cli::kVerify_Output_Description, false, "", "file");

        TCLAP::SwitchArg returnStatusArg("", "return-status", cli::kVerify_SwitchReturnStatus_Description, false);

        TCLAP::ValueArg<std::string> signArg("s", "sign", cli::kVerify_SignDigest_Description, true, "", "file");

        TCLAP::ValueArg<std::string> recipientArg("r", "recipient", cli::kVerify_Recipient_Description, true, "",
                                                  "arg");

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(recipientArg);
        cmd.add(signArg);
        cmd.add(returnStatusArg);
        cmd.add(outArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);

        auto recipientFormat = cli::parsePair(recipientArg.getValue());
        checkFormatRecipientArg(recipientFormat);

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

        // Verify data
        vcrypto::stream::VirgilStreamDataSource dataSource(*inStream);

        // Read sign
        std::ifstream signFile(signArg.getValue(), std::ios::in | std::ios::binary);
        if (!signFile) {
            throw std::invalid_argument("cannot read file: " + signArg.getValue());
        }
        vcrypto::VirgilByteArray sign((std::istreambuf_iterator<char>(signFile)), std::istreambuf_iterator<char>());

        std::string type = recipientFormat.first;
        std::string value = recipientFormat.second;
        vcrypto::VirgilByteArray publicKey;

        if (type == "pubkey") {
            std::string pathToPublicKeyFile = value;
            if (verboseArg.isSet()) {
                std::cout << "Read public key by path:" << value << std::endl;
            }
            publicKey = wsdk::readPublicKey(pathToPublicKeyFile);
        } else {
            // type [id|vcard]
            if (type == "id") {
                if (verboseArg.isSet()) {
                    std::cout << "Download a Virgil Card by id:" << value << std::endl;
                }
                wsdk::CardClient cardClient;
                auto card = cardClient.getCardById(value);
                publicKey = card.getPublicKey().getKey();
            } else {
                // vcard
                std::string pathCardFile = value;
                if (verboseArg.isSet()) {
                    std::cout << "Read a Virgil Card by path:" << pathCardFile << std::endl;
                }
                auto card = wsdk::readCard(pathCardFile);
                publicKey = card.getPublicKey().getKey();
            }
        }

        // Create signer
        vcrypto::VirgilStreamSigner signer;
        bool verified = signer.verify(dataSource, sign, publicKey);
        if (verified) {
            if (returnStatusArg.getValue()) {
                return EXIT_SUCCESS;
            } else {
                cli::writeBytes(outArg.getValue(), "success");
            }
        } else {
            if (returnStatusArg.getValue()) {
                return EXIT_FAILURE;
            } else {
                cli::writeBytes(outArg.getValue(), "failure");
            }
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "verify. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "verify. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void checkFormatRecipientArg(const std::pair<std::string, std::string>& pairRecipientArg) {
    const std::string type = pairRecipientArg.first;
    if (type != "id" && type != "vcard" && type != "pubkey") {
        throw std::invalid_argument("invalid type format: " + type + ". Expected format: '<key>:<value>'. "
                                                                     "Where <key> = [id|vcard|pubkey]");
    }
}
