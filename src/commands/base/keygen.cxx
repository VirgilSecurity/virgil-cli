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
#include <cli/util.h>

namespace vcrypto = virgil::crypto;
namespace vcli = virgil::cli;

/**
  * @brief Convert string representation of the Elliptic Curve group to the appropriate constant.
  */
static vcrypto::VirgilKeyPair::Type ec_key_group_from_param(const std::string& param);

/**
 * @brief Convert string representation of the RSA group to the appropriate constant.
 */
static vcrypto::VirgilKeyPair::Type rsa_key_group_from_param(const std::string& param);

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN keygen_main
#endif

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Generate Elliptic Curve Private Key or RSA Private Key.\n";

        std::vector<std::string> examples;
        examples.push_back("Generate Elliptic 512-bits Brainpool Curve Private Key(default):\n"
                           "virgil keygen -o alice/private.key\n");

        examples.push_back("Generate Elliptic Curve Private Key with password protection:\n"
                           "virgil keygen -o alice/private.key -p\n");

        examples.push_back("Generate Elliptic 521-bits NIST Curve Private Key:\n"
                           "virgil keygen -o alice/private.key -e secp521r1\n");

        examples.push_back("Generate RSA Private Key:\n"
                           "virgil keygen -o alice/private.key -r rsa8192\n");

        std::string descriptionMessage = vcli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Private key. If omitted, stdout is used.", false, "", "file");

        std::vector<std::string> ec_key;
        ec_key.push_back("bp256r1");
        ec_key.push_back("bp384r1");
        ec_key.push_back("bp512r1");
        ec_key.push_back("secp192r1");
        ec_key.push_back("secp224r1");
        ec_key.push_back("secp256r1");
        ec_key.push_back("secp384r1");
        ec_key.push_back("secp521r1");
        ec_key.push_back("secp192k1");
        ec_key.push_back("secp224k1");
        ec_key.push_back("secp256k1");
        TCLAP::ValuesConstraint<std::string> allowedEcKey(ec_key);

        TCLAP::ValueArg<std::string> ecArg("e", "ec", "Generate elliptic curve key with one of the following curves:\n"
                                                      "\t* bp256r1 - 256-bits Brainpool curve;\n"
                                                      "\t* bp384r1 - 384-bits Brainpool curve;\n"
                                                      "\t* bp512r1 - 512-bits Brainpool curve (default);\n"
                                                      "\t* secp192r1 - 192-bits NIST curve;\n"
                                                      "\t* secp224r1 - 224-bits NIST curve;\n"
                                                      "\t* secp256r1 - 256-bits NIST curve;\n"
                                                      "\t* secp384r1 - 384-bits NIST curve;\n"
                                                      "\t* secp521r1 - 521-bits NIST curve;\n"
                                                      "\t* secp192k1 - 192-bits \"Koblitz\" curve;\n"
                                                      "\t* secp224k1 - 224-bits \"Koblitz\" curve;\n"
                                                      "\t* secp256k1 - 256-bits \"Koblitz\" curve;\n",
                                           false, "", &allowedEcKey);

        std::vector<std::string> rsa_key;
        rsa_key.push_back("rsa3072");
        rsa_key.push_back("rsa4096");
        rsa_key.push_back("rsa8192");
        TCLAP::ValuesConstraint<std::string> allowedRSAKey(rsa_key);

        TCLAP::ValueArg<std::string> rsaArg("r", "rsa", "Generate RSA key with one of the following positions:\n"
                                                        "\t* rsa3072;\n"
                                                        "\t* rsa4096;\n"
                                                        "\t* rsa8192",
                                            false, "", &allowedRSAKey);

        TCLAP::SwitchArg privatePasswordArg("p", "key-pwd", "Password to be used for Private Key encryption.", false);

        cmd.add(privatePasswordArg);
        cmd.add(rsaArg);
        cmd.add(ecArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        // Check parameters
        if (ecArg.isSet() && rsaArg.isSet()) {
            throw std::invalid_argument("-e, --ec and -r, --rsa parameters are both specified");
        }

        vcrypto::VirgilByteArray privateKeyPassword;
        if (privatePasswordArg.isSet()) {
            std::cout << "Enter private key pass:" << std::endl;
            std::string pass;
            pass = vcli::inputShadow();
            // std::cout << "pass = " << pass << std::endl;
            privateKeyPassword = vcrypto::str2bytes(pass);
        }

        std::cout << std::endl;
        std::cout << "A Private key generating.." << std::endl;

        vcrypto::VirgilByteArray privateKey;
        if (!ecArg.isSet() && !rsaArg.isSet()) {
            // Generate EC key
            // bp512r1 - 512-bits Brainpool curve (default)
            vcrypto::VirgilKeyPair keyPair(privateKeyPassword);
            privateKey = keyPair.privateKey();
        } else {
            if (rsaArg.isSet()) {
                // Generate RSA key
                vcrypto::VirgilKeyPair::Type type = rsa_key_group_from_param(rsaArg.getValue());
                vcrypto::VirgilKeyPair keyPair = vcrypto::VirgilKeyPair::generate(type, privateKeyPassword);
                privateKey = keyPair.privateKey();
            } else {
                // Generate EC key
                vcrypto::VirgilKeyPair::Type type = ec_key_group_from_param(ecArg.getValue());
                vcrypto::VirgilKeyPair keyPair = vcrypto::VirgilKeyPair::generate(type, privateKeyPassword);
                privateKey = keyPair.privateKey();
            }
        }

        // Write private key
        virgil::cli::writeBytes(outArg.getValue(), privateKey);

        std::cout << "Private key has been generated" << std::endl;

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "key-gen. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "key-gen. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static vcrypto::VirgilKeyPair::Type ec_key_group_from_param(const std::string& param) {
    std::map<std::string, vcrypto::VirgilKeyPair::Type> ecKeyGroup;
    ecKeyGroup["secp192r1"] = vcrypto::VirgilKeyPair::Type_EC_SECP192R1;
    ecKeyGroup["secp224r1"] = vcrypto::VirgilKeyPair::Type_EC_SECP224R1;
    ecKeyGroup["secp256r1"] = vcrypto::VirgilKeyPair::Type_EC_SECP256R1;
    ecKeyGroup["secp384r1"] = vcrypto::VirgilKeyPair::Type_EC_SECP384R1;
    ecKeyGroup["secp521r1"] = vcrypto::VirgilKeyPair::Type_EC_SECP521R1;
    ecKeyGroup["bp256r1"] = vcrypto::VirgilKeyPair::Type_EC_BP256R1;
    ecKeyGroup["bp384r1"] = vcrypto::VirgilKeyPair::Type_EC_BP384R1;
    ecKeyGroup["bp512r1"] = vcrypto::VirgilKeyPair::Type_EC_BP512R1;
    ecKeyGroup["secp192k1"] = vcrypto::VirgilKeyPair::Type_EC_SECP192K1;
    ecKeyGroup["secp224k1"] = vcrypto::VirgilKeyPair::Type_EC_SECP224K1;
    ecKeyGroup["secp256k1"] = vcrypto::VirgilKeyPair::Type_EC_SECP256K1;

    auto group = ecKeyGroup.find(param);
    if (group != ecKeyGroup.end()) {
        return group->second;
    }

    return vcrypto::VirgilKeyPair::Type_Default;
}

static vcrypto::VirgilKeyPair::Type rsa_key_group_from_param(const std::string& param) {
    std::map<std::string, vcrypto::VirgilKeyPair::Type> ecKeyGroup;
    ecKeyGroup["rsa3072"] = vcrypto::VirgilKeyPair::Type_RSA_3072;
    ecKeyGroup["rsa4096"] = vcrypto::VirgilKeyPair::Type_RSA_4096;
    ecKeyGroup["rsa8192"] = vcrypto::VirgilKeyPair::Type_RSA_8192;

    auto group = ecKeyGroup.find(param);
    if (group != ecKeyGroup.end()) {
        return group->second;
    }

    return vcrypto::VirgilKeyPair::Type_Default;
}
