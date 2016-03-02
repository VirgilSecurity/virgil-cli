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
#include <string>
#include <vector>
#include <stdexcept>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace vcli = virgil::cli;


#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN card_create_main
#endif

int MAIN(int argc, char **argv) {
    try {
        std::string description = "Create card.\n";

        std::vector <std::string> examples;
        examples.push_back(
                "Create Card with confirm identity:\n"
                "virgil card-create -f <validated_identity.txt> "
                "--public-key <path_pub_key> -k <path_private_key> -o my_card.vcard\n");

        examples.push_back(
                "Create Card with confirm identity by pub-key-id:\n"
                "virgil card-create -f <validated_identity.txt> "
                "-e <pub_key_id> -k <path_private_key> -o my_card.vcard\n");

        examples.push_back(
                "Create Card with unconfirm identity:\n"
                "virgil card-create -d email:user@domain.com --public_key <path_pub_key> -k <path_private_key> "
                "-o my_card.vcard\n");

        examples.push_back(
                "Create Card with unconfirm identity by pub-key-id:\n"
                "virgil card-create -d email:user@domain.com -e <pub_key_id> -k <path_private_key> "
                "-o my_card.vcard\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Virgil Card. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> identityArg("d", "identity", "Identity email, phone etc",
                true, "", "arg");

        TCLAP::ValueArg<std::string> validatedIdentityArg("f", "validated-identities", "Validated identity",
                true, "", "file");

        TCLAP::ValueArg<std::string> publicKeyArg("", "public-key", "Public key",
                false, "", "file");

        TCLAP::ValueArg<std::string> publicKeyIdArg("e", "public-key-id", "Public key identifier",
                false, "", "arg");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "private-key", "Private key",
                true, "", "file");

        TCLAP::ValueArg<std::string> privateKeyPassArg("p", "private-pwd", "Private key pass",
                false, "", "arg");

        cmd.add(privateKeyPassArg);
        cmd.add(privateKeyArg);
        cmd.xorAdd(publicKeyArg, publicKeyIdArg);
        cmd.xorAdd(identityArg, validatedIdentityArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        vcrypto::VirgilByteArray publicKey;
        std::string publicKeyId;
        if (publicKeyArg.isSet()) {
            std::string pathPublicKey = publicKeyArg.getValue();
            publicKey = vcli::readFileBytes(pathPublicKey);
        } else {
            publicKeyId = publicKeyIdArg.getValue();
        }

        std::string pathPrivateKey = privateKeyArg.getValue();
        vcrypto::VirgilByteArray privateKey = vcli::readFileBytes(pathPrivateKey);

        vcrypto::VirgilByteArray privateKeyPass = vcrypto::str2bytes(privateKeyPassArg.getValue());
        vsdk::Credentials credentials(privateKey, privateKeyPass);

        vsdk::ServicesHub servicesHub(VIRGIL_ACCESS_TOKEN);
        vsdk::model::Card card;
        if (validatedIdentityArg.isSet()) {
            vsdk::model::ValidatedIdentity validatedIdentity =
                    vcli::readValidateIdentity(validatedIdentityArg.getValue());

            if (publicKeyArg.isSet()) {
                card = servicesHub.card().create(validatedIdentity, publicKey, credentials);
                if (outArg.isSet()) {
                    std::cout << "A card with a confirmed identity has been created." << std::endl;
                }
            } else {
                card = servicesHub.card().create(validatedIdentity, publicKeyId, credentials);
                if (outArg.isSet()) {
                    std::cout << "A card with a confirmed identity, which is connected with already existing one by"
                            " public-key-id has been created." << std::endl;
                }
            }

        } else {
            // identityArg.isSet
            auto identityPair = vcli::parsePair(identityArg.getValue());
            // check identity type: email
            std::string arg = "-d, --identity";
            vcli::checkFormatIdentity(arg, identityPair.first);
            std::string userEmail = identityPair.second;
            vsdk::model::Identity identity(userEmail, vsdk::model::IdentityType::Email);

            if (publicKeyArg.isSet()) {
                card = servicesHub.card().create(identity, publicKey, credentials);
                if (outArg.isSet()) {
                    std::cout << "A card with a unconfirmed identity has been created." << std::endl;
                }
            } else {
                card = servicesHub.card().create(identity, publicKeyId, credentials);
                if (outArg.isSet()) {
                    std::cout << "A card with a unconfirmed identity, which is connected with already existing one by"
                            " public-key-id, has been created." << std::endl;
                }
            }

        }

        std::string cardStr = vsdk::io::Marshaller<vsdk::model::Card>::toJson<4>(card);
        vcli::writeBytes(outArg.getValue(), cardStr);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "card-create. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "card-create. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
