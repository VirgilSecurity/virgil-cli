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
#include <fstream>
#include <iterator>

#include <tclap/CmdLine.h>

#include <virgil/crypto/foundation/VirgilPBKDF.h>

#include <virgil/sdk/util/obfuscator.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace vcli = virgil::cli;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN hash_main
#endif

static vcrypto::foundation::VirgilPBKDF::Hash hash_alg(const std::string& param);

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Derives the obfuscated data from incoming parameters using PBKDF function.\n\n";

        std::vector<std::string> examples;
        examples.push_back("Generate hash (alg - sha384, iterations - 2048 default):\n"
                           "virgil hash -i data.txt -o obfuscated_data.txt -s data_salt.txt\n\n");

        examples.push_back("Generate hash sha512 and count of iterations - 4096:\n"
                           "virgil hash -i data.txt -o obfuscated_data.txt -s data_salt.txt -a sha512 -c 4096\n\n");

        std::string descriptionMessage = vcli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "The string value to be hashed. If omitted, stdout is used.",
                                           false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Obfuscated data. If omitted, stdout is used.", false, "",
                                            "file");

        std::vector<std::string> alg;
        alg.push_back("sha1");
        alg.push_back("sha224");
        alg.push_back("sha256");
        alg.push_back("sha384");
        alg.push_back("sha512");
        TCLAP::ValuesConstraint<std::string> allowedAlg(alg);

        TCLAP::ValueArg<std::string> saltArg("s", "salt", "The hash salt.", true, "", "file");

        TCLAP::ValueArg<std::string> algorithmArg("a", "algorithm", "Generate hash with one"
                                                                    "of the following positions:\n"
                                                                    "\t* sha1 -   secure Hash Algorithm 1;\n"
                                                                    "\t* sha224 - hash algorithm;\n"
                                                                    "\t* sha256 - hash algorithm;\n"
                                                                    "\t* sha384 - hash algorithm(default);\n"
                                                                    "\t* sha512 - hash algorithm;\n",
                                                  false, "sha384", &allowedAlg);

        TCLAP::ValueArg<int> iterationsArg("c", "iterations", "The count of iterations. Default - 2048", false, 2048,
                                           "int");

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Show detailed information", false);

        cmd.add(verboseArg);
        cmd.add(iterationsArg);
        cmd.add(algorithmArg);
        cmd.add(saltArg);
        cmd.add(outArg);
        cmd.add(inArg);

        cmd.parse(argc, argv);

        if (verboseArg.isSet()) {
            std::cout << "Generating hash.." << std::endl;
        }

        std::string pathToSaltFile = saltArg.getValue();
        std::ifstream inSaltFile(pathToSaltFile, std::ios::in | std::ios::binary);
        if (!inSaltFile) {
            throw std::invalid_argument("can not read salt file by path: " + pathToSaltFile);
        }

        std::string salt((std::istreambuf_iterator<char>(inSaltFile)), std::istreambuf_iterator<char>());

        std::string value = vcli::readInput(inArg.getValue());
        auto sequenceBase64 = vsdk::util::obfuscate(value, saltArg.getValue(), hash_alg(algorithmArg.getValue()),
                                                    iterationsArg.getValue());
        vcli::writeOutput(outArg.getValue(), sequenceBase64);
        if (verboseArg.isSet()) {
            std::cout << "The hash generated" << std::endl;
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "hash. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "hash. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

vcrypto::foundation::VirgilPBKDF::Hash hash_alg(const std::string& param) {
    std::map<std::string, vcrypto::foundation::VirgilPBKDF::Hash> hashAlg;
    hashAlg["sha1"] = vcrypto::foundation::VirgilPBKDF::Hash::Hash_SHA1;
    hashAlg["sha224"] = vcrypto::foundation::VirgilPBKDF::Hash::Hash_SHA224;
    hashAlg["sha256"] = vcrypto::foundation::VirgilPBKDF::Hash::Hash_SHA256;
    hashAlg["sha384"] = vcrypto::foundation::VirgilPBKDF::Hash::Hash_SHA384;
    hashAlg["sha512"] = vcrypto::foundation::VirgilPBKDF::Hash::Hash_SHA512;

    auto group = hashAlg.find(param);
    if (group != hashAlg.end()) {
        return group->second;
    }

    return vcrypto::foundation::VirgilPBKDF::Hash::Hash_SHA384;
}
