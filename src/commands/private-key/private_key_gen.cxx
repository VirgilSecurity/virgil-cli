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
#include <virgil/crypto/foundation/VirgilKeyPairGenerator.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

#include <cli/version.h>
#include <cli/util.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilKeyPairGenerator;
using virgil::crypto::foundation::VirgilAsymmetricCipher;

// /**
//  * @brief Convert string representation of the Elliptic Curve group to the appropriate constant.
//  */
static VirgilKeyPairGenerator::ECKeyGroup ec_key_group_from_param(const std::string &param);

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN private_key_gen_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Generate private key with given parameters.", ' ', virgil::cli_version());

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

        TCLAP::ValueArg<std::string> ecArg("e", "ec",
                "Generate elliptic curve key with one of the following curves:\n"
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
                "\t* secp256k1 - 256-bits \"Koblitz\" curve.\n",
                false, "", &allowedEcKey);

        TCLAP::ValueArg<unsigned int> rsaArg("r", "rsa", "Generate RSA key with a given number of bits.",
                false, 0, "nbits");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Private key. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> privatePasswordArg("p", "private-pwd", "Password to be used for private key encryption. "
                "If omitted private key is stored in the plain format.", false, "", "arg");

        cmd.add(privatePasswordArg);
        cmd.add(outArg);
        cmd.add(ecArg);
        cmd.add(rsaArg);
        cmd.parse(argc, argv);

        // Check parameters
        if (ecArg.isSet() && rsaArg.isSet()) {
            throw std::invalid_argument("-e, --ec and -r, --rsa parameters are both specified");
        }

        VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
        if (rsaArg.isSet()) {
            // Generate RSA key
            cipher = VirgilAsymmetricCipher::rsa();
            cipher.genKeyPair(VirgilKeyPairGenerator::rsa(rsaArg.getValue()));
        } else {
            // Generate EC key
            VirgilKeyPairGenerator::ECKeyGroup ecKeyGroup = ec_key_group_from_param(ecArg.getValue());
            if (ecKeyGroup == VirgilKeyPairGenerator::ECKeyGroup_DP_NONE) {
                if (ecArg.getValue().empty()) {
                    ecKeyGroup = VirgilKeyPairGenerator::ECKeyGroup_DP_BP512R1;
                } else {
                    throw std::invalid_argument(std::string("unknown elliptic curve: ") + ecArg.getValue());
                }
            }
            cipher = VirgilAsymmetricCipher::ec();
            cipher.genKeyPair(VirgilKeyPairGenerator::ec(ecKeyGroup));
        }

        // Export private key
        VirgilByteArray privateKey = cipher.exportPrivateKeyToPEM(virgil::crypto::str2bytes(privatePasswordArg.getValue()));

        // Write private key
        virgil::cli::write_bytes(outArg.getValue(), privateKey);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "private-key-gen. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "private-key-gen. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static VirgilKeyPairGenerator::ECKeyGroup ec_key_group_from_param(const std::string &param) {
    std::map<std::string, VirgilKeyPairGenerator::ECKeyGroup> ecKeyGroup;
    ecKeyGroup["secp192r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP192R1;
    ecKeyGroup["secp224r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP224R1;
    ecKeyGroup["secp256r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP256R1;
    ecKeyGroup["secp384r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP384R1;
    ecKeyGroup["secp521r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP521R1;
    ecKeyGroup["bp256r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_BP256R1;
    ecKeyGroup["bp384r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_BP384R1;
    ecKeyGroup["bp512r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_BP512R1;
    ecKeyGroup["secp192k1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP192K1;
    ecKeyGroup["secp224k1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP224K1;
    ecKeyGroup["secp256k1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP256K1;

    auto group = ecKeyGroup.find(param);
    if (group != ecKeyGroup.end()) {
        return group->second;
    }
    return VirgilKeyPairGenerator::ECKeyGroup_DP_NONE;
}
