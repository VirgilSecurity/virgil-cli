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

#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace vcli = virgil::cli;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN card_create_global_main
#endif

int MAIN(int argc, char** argv) {
    try {
        std::vector<std::string> examples;
        examples.push_back("Create a Global Virgil Card:\n"
                           "virgil card-create-global -f alice/validated_identity_global.txt "
                           "--public-key public.key -k alice/private.key -o alice/my_card.vcard\n\n");

        examples.push_back("Create a Global Virgil Card, with Identity confirmation:\n"
                           "virgil card-create-global -d alice@domain.com "
                           "--public-key public.key -k alice/private.key -o alice/my_card.vcard\n\n");

        examples.push_back("Create a connection with already existing the Global Virgil Card, "
                           "by public-key-id:\n"
                           "virgil card-create-global -f alice/validated_identity_global.txt "
                           "-e <pub_key_id> -k alice/private.key -o alice/my_card.vcard\n\n");

        examples.push_back("Create a connection with already existing Global Virgil Card, by public-key-id."
                           "With confirming of identity:\n"
                           "virgil card-create-global -d alice@domain.com "
                           "-e <pub_key_id> -k alice/private.key -o alice/my_card.vcard\n\n");

        std::string descriptionMessage =
            virgil::cli::getDescriptionMessage(vcli::kCardCreateGlobal_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Global Virgil Card. If omitted, stdout is used.", false, "",
                                            "file");

        TCLAP::ValueArg<std::string> validatedIdentityArg(
            vcli::kValidatedIdentity_ShortName, vcli::kValidatedIdentity_LongName,
            vcli::kGlobalValidatedIdentity_Description, true, "", vcli::kValidatedIdentity_TypeDesc);

        TCLAP::ValueArg<std::string> identityArg(vcli::kIdentity_ShortName, vcli::kIdentity_LongName,
                                                 vcli::kGlobalIdentity_Description, true, "",
                                                 vcli::kIdentity_TypedDesc);

        TCLAP::ValueArg<std::string> publicKeyArg("", "public-key", "Public key", true, "", "file");

        TCLAP::ValueArg<std::string> publicKeyIdArg(vcli::kPublicKeyId_ShortName, vcli::kPublicKeyId_LongName,
                                                    vcli::kPublicKeyId_Description, true, "",
                                                    vcli::kPublicKeyId_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyArg(vcli::kPrivateKey_ShortName, vcli::kPrivateKey_LongName,
                                                   vcli::kPrivateKey_Description, true, "", vcli::kPrivateKey_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            vcli::kPrivateKeyPassword_ShortName, vcli::kPrivateKeyPassword_LongName,
            vcli::kPrivateKeyPassword_Description, false, "", vcli::kPrivateKeyPassword_TypeDesc);

        TCLAP::SwitchArg verboseArg(vcli::kVerbose_ShortName, vcli::kVerbose_LongName, vcli::kVerbose_Description,
                                    false);

        cmd.add(verboseArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(privateKeyArg);
        cmd.xorAdd(publicKeyIdArg, publicKeyArg);
        cmd.xorAdd(identityArg, validatedIdentityArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        std::string pathPrivateKey = privateKeyArg.getValue();
        vcrypto::VirgilByteArray privateKey = vcli::readPrivateKey(pathPrivateKey);
        vcrypto::VirgilByteArray privateKeyPassword;
        if (privateKeyPasswordArg.isSet()) {
            privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
        } else {
            privateKeyPassword = vcli::setPrivateKeyPass(privateKey);
        }

        vcrypto::VirgilByteArray publicKey;
        std::string publicKeyId;
        if (publicKeyArg.isSet()) {
            std::string pathPublicKey = publicKeyArg.getValue();
            publicKey = vcli::readFileBytes(pathPublicKey);
            if (!vcrypto::VirgilKeyPair::isKeyPairMatch(publicKey, privateKey, privateKeyPassword)) {
                throw std::runtime_error("Public key and Private key doesn't math to each other");
            }

        } else {
            // publicKeyId.isSet
            publicKeyId = publicKeyIdArg.getValue();
        }

        vsdk::Credentials credentials(privateKey, privateKeyPassword);

        vcli::ConfigFile configFile = vcli::readConfigFile();
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.serviceUri);

        vsdk::models::CardModel card;
        if (validatedIdentityArg.isSet()) {
            vsdk::dto::ValidatedIdentity validatedIdentity =
                vcli::readValidateIdentity(validatedIdentityArg.getValue());
            if (publicKeyArg.isSet()) {
                card = servicesHub.card().create(validatedIdentity, publicKey, credentials);
                if (verboseArg.isSet()) {
                    std::cout << "A Global Virgil Card has been created." << std::endl;
                }
            } else {
                card = servicesHub.card().create(validatedIdentity, publicKeyId, credentials);
                if (verboseArg.isSet()) {
                    std::cout << "A Global Virgil Card which is connected with already "
                                 "existing one by public-key-id has been created."
                              << std::endl;
                }
            }
        } else {
            std::string recipientType = "email";
            std::string recipientValue = identityArg.getValue();

            std::string actionId =
                servicesHub.identity().verify(recipientValue, vsdk::dto::VerifiableIdentityType::Email);
            if (verboseArg.isSet()) {
                std::cout << "Send confirmation-code to " << recipientValue << std::endl;
            }

            std::cout << "Enter confirmation code which was sent on you identity - " << recipientType << ":"
                      << recipientValue << std::endl;
            std::string confirmationCode = vcli::inputShadow();

            if (verboseArg.isSet()) {
                std::cout << "Confirme identity " << recipientValue << std::endl;
            }

            vsdk::dto::ValidatedIdentity validatedIdentity = servicesHub.identity().confirm(actionId, confirmationCode);
            if (verboseArg.isSet()) {
                std::cout << "An Identity " << recipientType << ":" << recipientValue << " is confirmed" << std::endl;
            }

            if (publicKeyArg.isSet()) {
                card = servicesHub.card().create(validatedIdentity, publicKey, credentials);
                if (verboseArg.isSet()) {
                    std::cout << "A Global Virgil Card has been created." << std::endl;
                }
            } else {
                // publicKeyIdArg
                card = servicesHub.card().create(validatedIdentity, publicKeyId, credentials);
                if (verboseArg.isSet()) {
                    std::cout << "A Global Virgil Card which is connected with already "
                                 "existing one by public-key-id="
                              << publicKeyId << " has been created." << std::endl;
                }
            }
        }

        std::string cardStr = vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(card);
        vcli::writeBytes(outArg.getValue(), cardStr);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "card-create-global. Error: " << exception.error() << " for arg " << exception.argId()
                  << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "card-create-global. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
