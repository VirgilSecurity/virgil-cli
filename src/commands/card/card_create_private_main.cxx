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
#include <vector>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilKeyPair.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>
#include <cli/wrapper/sdk/PrivateKey.h>
#include <cli/wrapper/sdk/PublicKey.h>
#include <cli/wrapper/sdk/ValidatedIdentity.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace wsdk = cli::wrapper::sdk;

int card_create_private_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Create a private Virgil Card with a confirmed identity:\n"
            "\tvirgil card-create-private -f validated_identity.txt "
            "--public-key public.key -k private.key -o my_card.vcard\n\n"

            "2. Create a connection with an already existing a private Virgil Card with a confirmed "
            "Identity by public-key-id:\n"
            "\tvirgil card-create-private -f alice/validated_identity.txt "
            "-e <pub_key_id> -k alice/private.key -o alice/my_card.vcard\n\n"

            "3. Create a private Virgil Card with an unconfirmed Identity:\n"
            "\tvirgil card-create-private -d <identity_type>:<identity_value> --public_key "
            "alice/public.key -k alice/private.key "
            "-o alice/anonim_card1.vcard\n\n"

            "4. Create a connection with an already existing a Private Virgil Card with an unconfirmed"
            "Identity by public-key-id:\n"
            "\tvirgil card-create-private -d <identity_type>:<identity_value> -e <pub_key_id> -k alice/private.key "
            "-o alice/anonim_card2.vcard\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kCardCreatePrivate_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Private Virgil Card. If omitted, stdout is used.", false, "",
                                            "file");

        TCLAP::ValueArg<std::string> identityArg(cli::kIdentity_ShortName, cli::kIdentity_LongName,
                                                 cli::kGlobalIdentity_Description, true, "", cli::kIdentity_TypedDesc);

        TCLAP::ValueArg<std::string> validatedIdentityArg(
            cli::kValidatedIdentity_ShortName, cli::kValidatedIdentity_LongName, cli::kPrivateIdentity_Description,
            true, "", cli::kValidatedIdentity_TypeDesc);

        TCLAP::ValueArg<std::string> publicKeyArg("", "public-key", "Public key", true, "", "file");

        TCLAP::ValueArg<std::string> publicKeyIdArg(cli::kPublicKeyId_ShortName, cli::kPublicKeyId_LongName,
                                                    cli::kPublicKeyId_Description, true, "",
                                                    cli::kPublicKeyId_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyArg(cli::kPrivateKey_ShortName, cli::kPrivateKey_LongName,
                                                   cli::kPrivateKey_Description, true, "", cli::kPrivateKey_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            cli::kPrivateKeyPassword_ShortName, cli::kPrivateKeyPassword_LongName, cli::kPrivateKeyPassword_Description,
            false, "", cli::kPrivateKeyPassword_TypeDesc);

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(privateKeyArg);
        cmd.xorAdd(publicKeyArg, publicKeyIdArg);
        cmd.xorAdd(identityArg, validatedIdentityArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        std::string pathPrivateKey = privateKeyArg.getValue();
        vcrypto::VirgilByteArray privateKey = wsdk::readPrivateKey(pathPrivateKey);
        vcrypto::VirgilByteArray privateKeyPassword;
        if (privateKeyPasswordArg.isSet()) {
            privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
        } else {
            privateKeyPassword = cli::setPrivateKeyPass(privateKey);
        }

        vcrypto::VirgilByteArray publicKey;
        std::string publicKeyId;
        if (publicKeyArg.isSet()) {
            std::string pathPublicKey = publicKeyArg.getValue();
            publicKey = wsdk::readPublicKey(pathPublicKey);
            if (!vcrypto::VirgilKeyPair::isKeyPairMatch(publicKey, privateKey, privateKeyPassword)) {
                throw std::runtime_error("Public key and Private key doesn't math to each other");
            }

        } else {
            // publicKeyId.isSet
            publicKeyId = publicKeyIdArg.getValue();
        }

        vsdk::Credentials credentials(privateKey, privateKeyPassword);

        cli::ConfigFile configFile = cli::readConfigFile();
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.getServiceUri());

        vsdk::models::CardModel card;
        if (validatedIdentityArg.isSet()) {
            vsdk::dto::ValidatedIdentity validatedIdentity =
                wsdk::readValidatedIdentity(validatedIdentityArg.getValue());
            if (publicKeyArg.isSet()) {
                card = servicesHub.card().create(validatedIdentity, publicKey, credentials);
                if (verboseArg.isSet()) {
                    std::cout << "A Private Virgil Card with a confirmed identity has been created." << std::endl;
                }
            } else {
                card = servicesHub.card().create(validatedIdentity, publicKeyId, credentials);
                if (verboseArg.isSet()) {
                    std::cout << "A Private Virgil Card with a confirmed identity, which is connected with already "
                                 "existing one by"
                                 " public-key-id has been created."
                              << std::endl;
                }
            }
        } else {
            // identityArg.isSet
            auto identityPair = cli::parsePair(identityArg.getValue());
            std::string recipientType = identityPair.first;
            std::string recipientValue = identityPair.second;
            vsdk::dto::Identity identity(recipientValue, recipientType);

            if (publicKeyArg.isSet()) {
                card = servicesHub.card().create(identity, publicKey, credentials);
                if (verboseArg.isSet()) {
                    std::cout << "A Private Virgil Card with an unconfirmed identity has been created." << std::endl;
                }
            } else {
                card = servicesHub.card().create(identity, publicKeyId, credentials);
                if (verboseArg.isSet()) {
                    std::cout << "A Private Virgil Card with an unconfirmed identity, which is connected with already "
                                 "existing one by"
                                 " public-key-id, has been created."
                              << std::endl;
                }
            }
        }

        std::string cardStr = vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(card);
        cli::writeBytes(outArg.getValue(), cardStr);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "card-create-private. Error: " << exception.error() << " for arg " << exception.argId()
                  << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "card-create-private. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
