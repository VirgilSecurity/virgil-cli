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

#include <iostream>
#include <fstream>

#include <tclap/CmdLine.h>

#include <virgil/crypto/foundation/VirgilPBKDF.h>

#include <virgil/sdk/util/obfuscator.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;

static vcrypto::foundation::VirgilPBKDF::Hash hash_alg(const std::string& param);

int exhash_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Underlying hash - SHA384 (default), iterations - 2048 (default):\n"
            "\tvirgil exhash -i data.txt -o obfuscated_data.txt -s data_salt.txt\n\n",

            "2. Underlying hash - SHA512, iterations - 4096:\n"
            "\tvirgil exhash -i data.txt -o obfuscated_data.txt -s data_salt.txt -a sha512 -c 4096\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kExhash_Descritpion, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", cli::kExhash_Input_Description, false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", cli::kExhash_Output_Description, false, "", "file");

        std::vector<std::string> alg;
        alg.push_back("sha1");
        alg.push_back("sha224");
        alg.push_back("sha256");
        alg.push_back("sha384");
        alg.push_back("sha512");
        TCLAP::ValuesConstraint<std::string> allowedAlg(alg);

        TCLAP::ValueArg<std::string> saltArg("s", "salt", cli::kExhash_Salt_Descritpion, true, "", "file");

        TCLAP::ValueArg<std::string> algorithmArg("a", "algorithm", cli::kExhash_Algorithm_Description, false, "sha384",
                                                  &allowedAlg);

        TCLAP::ValueArg<int> iterationsArg("c", "iterations", cli::kExhash_Iterations_Description, false, 2048, "int");

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

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

        std::string value = cli::readInput(inArg.getValue());
        auto sequenceBase64 = vsdk::util::obfuscate(value, saltArg.getValue(), hash_alg(algorithmArg.getValue()),
                                                    iterationsArg.getValue());
        cli::writeOutput(outArg.getValue(), sequenceBase64);
        if (verboseArg.isSet()) {
            std::cout << "The hash generated" << std::endl;
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "exhash. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "exhash. Error: " << exception.what() << std::endl;
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
