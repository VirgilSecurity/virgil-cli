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
#include <iostream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>

namespace vcrypto = virgil::crypto;
namespace vcli = virgil::cli;

/**
  * @brief Convert string representation of the Elliptic Curve or RSA group to the appropriate constant.
  */
static vcrypto::VirgilKeyPair::Type key_group_from_param(const std::string& param);

static void printProcessGeneratingPrivate(const std::string& algorithmType);

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN keygen_main
#endif

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Generate Elliptic Curve or RSA Private Key.\n\n";

        std::vector<std::string> examples;
        examples.push_back("Generate Curve25519 Private Key(default), your password will be requested:\n"
                           "virgil keygen -o alice/private.key\n\n");

        examples.push_back("Generate Elliptic Curve Private Key with password protection:\n"
                           "virgil keygen -o alice/private.key\n\n");

        examples.push_back("Generate Elliptic 521-bits NIST Curve Private Key, your password will be requested:\n"
                           "virgil keygen -o alice/private.key -a secp521r1\n\n");

        examples.push_back("Generate 8192-bits RSA Private Key, your password will be requested:\n"
                           "virgil keygen -o alice/private.key -a rsa8192\n\n");

        std::string descriptionMessage = vcli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Private key. If omitted, stdout is used.", false, "", "file");

        std::vector<std::string> alg;
        alg.push_back("bp256r1");
        alg.push_back("bp384r1");
        alg.push_back("bp512r1");
        alg.push_back("secp192r1");
        alg.push_back("secp224r1");
        alg.push_back("secp256r1");
        alg.push_back("secp384r1");
        alg.push_back("secp521r1");
        alg.push_back("secp192k1");
        alg.push_back("secp224k1");
        alg.push_back("secp256k1");
        alg.push_back("ed25519");
        alg.push_back("rsa3072");
        alg.push_back("rsa4096");
        alg.push_back("rsa8192");
        TCLAP::ValuesConstraint<std::string> allowedAlg(alg);

        TCLAP::ValueArg<std::string> algorithmArg("a", "algorithm", "Generate elliptic curve key or RSA key with one"
                                                                    "of the following positions:\n"
                                                                    "\t* bp256r1 - 256-bits Brainpool curve;\n"
                                                                    "\t* bp384r1 - 384-bits Brainpool curve;\n"
                                                                    "\t* bp512r1 - 512-bits Brainpool curve;\n"
                                                                    "\t* secp192r1 - 192-bits NIST curve;\n"
                                                                    "\t* secp224r1 - 224-bits NIST curve;\n"
                                                                    "\t* secp256r1 - 256-bits NIST curve;\n"
                                                                    "\t* secp384r1 - 384-bits NIST curve;\n"
                                                                    "\t* secp521r1 - 521-bits NIST curve;\n"
                                                                    "\t* secp192k1 - 192-bits \"Koblitz\" curve;\n"
                                                                    "\t* secp224k1 - 224-bits \"Koblitz\" curve;\n"
                                                                    "\t* secp256k1 - 256-bits \"Koblitz\" curve;\n"
                                                                    "\t* ed25519 - Curve25519 (default);\n"
                                                                    "\t* rsa3072 - 3072-bits \"RSA\" key;\n"
                                                                    "\t* rsa4096 - 4096-bits \"RSA\" key;\n"
                                                                    "\t* rsa8192 - 8192-bits \"RSA\" key",
                                                  false, "secp384r1", &allowedAlg);

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            "p", "private-key-password", "Password to be used for Private Key encryption.", false, "", "arg");

        TCLAP::SwitchArg notShadowInputArg(
            "", "no-password-input", "If parameter -p, --private-key-password is omitted, password won’t be requested.",
            false);

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Show detailed information", false);

        cmd.add(verboseArg);
        cmd.add(notShadowInputArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(algorithmArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        vcrypto::VirgilByteArray privateKey;
        vcrypto::VirgilByteArray privateKeyPassword;

        if (privateKeyPasswordArg.isSet()) {
            privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
        } else {
            if (!notShadowInputArg.isSet()) {
                std::cout << "Do you want add password to be used for Private Key encryption[Y/n] ?" << std::endl;
                std::string answer;
                std::cin >> answer;
                if (answer == "Y" || answer == "y") {
                    std::cout << "Enter private key password:" << std::endl;
                    std::string password = vcli::inputShadow();
                    privateKeyPassword = vcrypto::str2bytes(password);
                    std::cout << std::endl;
                }
            }
        }

        // default algorithmArg = secp384r1
        std::string algorithmType = algorithmArg.getValue();
        if (verboseArg.isSet()) {
            printProcessGeneratingPrivate(algorithmType);
        }

        if (!algorithmArg.isSet()) {
            vcrypto::VirgilKeyPair keyPair(privateKeyPassword);
            privateKey = keyPair.privateKey();
        } else {
            vcrypto::VirgilKeyPair::Type type = key_group_from_param(algorithmType);
            vcrypto::VirgilKeyPair keyPair = vcrypto::VirgilKeyPair::generate(type, privateKeyPassword);
            privateKey = keyPair.privateKey();
        }

        vcli::writeBytes(outArg.getValue(), privateKey);
        if (verboseArg.isSet()) {
            std::cout << "Private key has been generated.\n";
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "key-gen. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "key-gen. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static vcrypto::VirgilKeyPair::Type key_group_from_param(const std::string& param) {
    std::map<std::string, vcrypto::VirgilKeyPair::Type> keyGroup;
    keyGroup["bp256r1"] = vcrypto::VirgilKeyPair::Type_EC_BP256R1;
    keyGroup["bp384r1"] = vcrypto::VirgilKeyPair::Type_EC_BP384R1;
    keyGroup["bp512r1"] = vcrypto::VirgilKeyPair::Type_EC_BP512R1;
    keyGroup["secp192r1"] = vcrypto::VirgilKeyPair::Type_EC_SECP192R1;
    keyGroup["secp224r1"] = vcrypto::VirgilKeyPair::Type_EC_SECP224R1;
    keyGroup["secp256r1"] = vcrypto::VirgilKeyPair::Type_EC_SECP256R1;
    keyGroup["secp384r1"] = vcrypto::VirgilKeyPair::Type_EC_SECP384R1;
    keyGroup["secp521r1"] = vcrypto::VirgilKeyPair::Type_EC_SECP521R1;
    keyGroup["secp192k1"] = vcrypto::VirgilKeyPair::Type_EC_SECP192K1;
    keyGroup["secp224k1"] = vcrypto::VirgilKeyPair::Type_EC_SECP224K1;
    keyGroup["secp256k1"] = vcrypto::VirgilKeyPair::Type_EC_SECP256K1;
    keyGroup["ed25519"] = vcrypto::VirgilKeyPair::Type_EC_M255;
    keyGroup["rsa3072"] = vcrypto::VirgilKeyPair::Type_RSA_3072;
    keyGroup["rsa4096"] = vcrypto::VirgilKeyPair::Type_RSA_4096;
    keyGroup["rsa8192"] = vcrypto::VirgilKeyPair::Type_RSA_8192;

    auto group = keyGroup.find(param);
    if (group != keyGroup.end()) {
        return group->second;
    }

    return vcrypto::VirgilKeyPair::Type_Default;
}

static void printProcessGeneratingPrivate(const std::string& algorithmType) {
    std::map<std::string, std::string> algTypeDescription;
    algTypeDescription["bp256r1"] = "256-bits Brainpool curve";
    algTypeDescription["bp384r1"] = "384-bits Brainpool curve";
    algTypeDescription["bp512r1"] = "512-bits Brainpool curve";
    algTypeDescription["secp192r1"] = "192-bits NIST curve";
    algTypeDescription["secp224r1"] = "224-bits NIST curve";
    algTypeDescription["secp256r1"] = "256-bits Brainpool curve";
    algTypeDescription["secp384r1"] = "384-bits NIST curve";
    algTypeDescription["secp521r1"] = "521-bits NIST curve";
    algTypeDescription["secp192k1"] = "192-bits \"Koblitz\" curve";
    algTypeDescription["secp224k1"] = "224-bits \"Koblitz\" curve";
    algTypeDescription["secp256k1"] = "256-bits \"Koblitz\" curve";
    algTypeDescription["ed25519"] = "Curve25519 (default)";
    algTypeDescription["rsa3072"] = "RSA 3072-bits ";
    algTypeDescription["rsa4096"] = "RSA 4096-bits";
    algTypeDescription["rsa8192"] = "RSA 8192-bits";

    std::cout << "Generating " + algTypeDescription[algorithmType] + " private key...\n";
}
