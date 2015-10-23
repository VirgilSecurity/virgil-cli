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
#include <iterator>
#include <stdexcept>
#include <string>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamSigner.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>

#include <cli/version.h>
#include <cli/util.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilStreamSigner;
using virgil::crypto::stream::VirgilStreamDataSource;

#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN sign_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Sign data with given user's private key.", ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be signed. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Digest sign. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "private-key", "Signer's private key.",
                true, "", "file");

        TCLAP::ValueArg<std::string> privatePasswordArg("p", "private-pwd", "Signer's private key password.",
                false, "", "arg");

        cmd.add(privatePasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(outArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);

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

        // Read private key
        std::ifstream keyFile(privateKeyArg.getValue(), std::ios::in | std::ios::binary);
        if (!keyFile) {
            throw std::invalid_argument("can not read file: " + privateKeyArg.getValue());
        }

        VirgilByteArray privateKey((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());
        VirgilByteArray privateKeyPassword = virgil::crypto::str2bytes(privatePasswordArg.getValue());

        // Create signer
        VirgilStreamSigner signer;

        // Sign data
        VirgilStreamDataSource dataSource(*inStream);
        VirgilByteArray sign = signer.sign(dataSource, privateKey, privateKeyPassword);

        // Prepare output. Write sign to the output.
        virgil::cli::write_bytes(outArg.getValue(), sign);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "sing. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "sign. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
