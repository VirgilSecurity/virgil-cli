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

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>

#include <virgil/sdk/keys/model/PublicKey.h>

#include <cli/util.h>
#include <cli/version.h>

using virgil::crypto::VirgilByteArray;

using virgil::crypto::VirgilStreamCipher;
using virgil::crypto::stream::VirgilStreamDataSource;
using virgil::crypto::stream::VirgilStreamDataSink;

using virgil::sdk::keys::model::PublicKey;

#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN decrypt_main
#endif

int MAIN(int argc, char **argv) {
     try {
         // Parse arguments.
         TCLAP::CmdLine cmd("Decrypt data with given password or user's private key", ' ', virgil::cli_version());

         TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be decrypted. If omitted stdin is used.",
                 false, "", "file");

         TCLAP::ValueArg<std::string> outArg("o", "out", "Decrypted data. If omitted stdout is used.",
                 false, "", "file");

         TCLAP::ValueArg<std::string> contentInfoArg("c", "content-info",
                 "Content info. Use this option if content info is not embedded in the encrypted data.",
                 false, "", "file");

         TCLAP::ValueArg<std::string> privateKeyArg("k", "private-key", "Recipient's private key.",
                 false, "", "file");

         TCLAP::ValueArg<std::string> privatePasswordArg("p", "private-pwd", "Recipient's private key password",
            false, "", "arg");

         TCLAP::ValueArg<std::string> recipientArg("r", "recipient",
                 "If option --key is defined this value is used as recipient's Virgil Public Key, "
                 "otherwise this value is used as recipient's password.",
                 true, "", "arg");

         cmd.add(recipientArg);
         cmd.add(privatePasswordArg);
         cmd.add(privateKeyArg);
         cmd.add(contentInfoArg);
         cmd.add(outArg);
         cmd.add(inArg);
         cmd.parse(argc, argv);

         // Create cipher
         VirgilStreamCipher cipher;

         if(!contentInfoArg.getValue().empty()) {
             // Set content info.
             std::ifstream contentInfoFile(contentInfoArg.getValue(), std::ios::in | std::ios::binary);
             if (contentInfoFile) {
                 throw std::invalid_argument("can not read file: " + contentInfoArg.getValue());
             }

             VirgilByteArray contentInfo((std::istreambuf_iterator<char>(contentInfoFile)),
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
         if (outArg.getValue().empty() || outArg.getValue() == "-") {
             outStream = &std::cout;
         } else {
             outFile.open(outArg.getValue(), std::ios::out | std::ios::binary);
             if (!outFile) {
                 throw std::invalid_argument("can not write file: " + outArg.getValue());
             }
             outStream = &outFile;
         }

         // Create IO streams
         VirgilStreamDataSource dataSource(*inStream);
         VirgilStreamDataSink dataSink(*outStream);

         // Process
         if (!privateKeyArg.getValue().empty()) {
             // Read Virgil Public Key
             std::ifstream virgilPublicKeyFile(recipientArg.getValue(), std::ios::in | std::ios::binary);
             if (!virgilPublicKeyFile) {
                 throw std::invalid_argument("can not read recipient's Virgil Public Key: " + recipientArg.getValue());
             }
             PublicKey publicKey = virgil::cli::read_virgil_public_key(virgilPublicKeyFile);

             // Define recipient identifier
             VirgilByteArray publicKeyId = virgil::crypto::str2bytes(publicKey.publicKeyId());

             // Read private key
             std::ifstream keyFile(privateKeyArg.getValue(), std::ios::in | std::ios::binary);
             if (!keyFile) {
                 throw std::invalid_argument("can not read private key: " + privateKeyArg.getValue());
             }
             VirgilByteArray privateKey((std::istreambuf_iterator<char>(keyFile)),
                         std::istreambuf_iterator<char>());

             VirgilByteArray privateKeyPassword = virgil::crypto::str2bytes(privatePasswordArg.getValue());

             // Decrypt
             cipher.decryptWithKey(dataSource, dataSink, publicKeyId, privateKey, privateKeyPassword);

         } else if (!recipientArg.getValue().empty()) {
             cipher.decryptWithPassword(dataSource, dataSink, virgil::crypto::str2bytes(recipientArg.getValue()));
         } else {
             throw std::invalid_argument("no recipients are defined");
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
