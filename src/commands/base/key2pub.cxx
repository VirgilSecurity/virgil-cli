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

#include <stdexcept>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/models/PrivateKeyModel.h>

#include <cli/version.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>
#include <cli/wrapper/sdk/PrivateKey.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace wsdk = cli::wrapper::sdk;

/**
 * @brief Returns whether underling data is ASN.1 structure or not.
 */
inline bool is_asn1(const vcrypto::VirgilByteArray& data) {
    return data.size() > 0 && data[0] == 0x30;
}

int key2pub_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{"1. Extract public key from private key:\n"
                                          "\tvirgil key2pub -i private.key -o public.key\n\n",

                                          "2. Extract public key from private key with password:\n"
                                          "\tvirgil key2pub -i private.key -o public.key -p STRONGPASS\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kKey2pub_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", cli::kKey2pub_Description, false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", cli::kKey2pub_Output_Description, false, "", "file");

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            cli::kPrivateKeyPassword_ShortName, cli::kPrivateKeyPassword_LongName, cli::kPrivateKeyPassword_Description,
            false, "", cli::kPrivateKeyPassword_TypeDesc);

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(outArg);
        cmd.add(inArg);
        cmd.parse(argc, argv);

        // Prepare input. Read private key.
        std::string privateKeyStr = cli::readInput(inArg.getValue());
        vcrypto::VirgilByteArray privateKey;
        if (wsdk::isPrivateKeyModel(privateKeyStr)) {
            vsdk::models::PrivateKeyModel privateKeyModel =
                vsdk::io::Marshaller<vsdk::models::PrivateKeyModel>::fromJson(privateKeyStr);
            privateKey = privateKeyModel.getKey();
        } else {
            privateKey = vcrypto::str2bytes(privateKeyStr);
        }

        vcrypto::VirgilByteArray privateKeyPassword;
        if (privateKeyPasswordArg.isSet()) {
            privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
        } else {
            privateKeyPassword = cli::setPrivateKeyPass(privateKey);
        }

        // Extract public key.
        vcrypto::foundation::VirgilAsymmetricCipher cipher;
        cipher.setPrivateKey(privateKey, privateKeyPassword);

        vcrypto::VirgilByteArray publicKey =
            is_asn1(privateKey) ? cipher.exportPublicKeyToDER() : cipher.exportPublicKeyToPEM();

        cli::writeBytes(outArg.getValue(), publicKey);
        if (verboseArg.isSet()) {
            std::cout << "Public Key has been extracted from the Private Key" << std::endl;
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "key2pub. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "key2pub. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
