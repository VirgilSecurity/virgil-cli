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

#include <algorithm>
#include <fstream>
#include <iostream>
#include <vector>

#include <tclap/CmdLine.h>

#include <virgil/sdk/ServicesHub.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>
#include <cli/wrapper/sdk/PrivateKey.h>
#include <cli/wrapper/sdk/ValidatedIdentity.h>
#include <cli/InputShadow.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;
namespace wsdk = cli::wrapper::sdk;

static vsdk::dto::ValidatedIdentity getValidatedIdentity(const bool verbose, const std::string& identityValue,
                                                         vsdk::ServicesHub& servicesHub);

int public_key_revoke_global_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Revoke a chain of global Virgil Cards by public-key-id from Virgil Keys Service:\n"
            "\tvirgil public-key-revoke-global -e <public_key_id> -a <card_id> -k alice/private.key"
            " -f alice/validated-identity-main.txt -f alice/validated-identity-reserve.txt\n\n",

            "2. Revoke a chain of global Virgil Cards by public-key-id from Virgil Keys Service, "
            "with confirming of identity:\n"
            "\tvirgil public-key-revoke-global -e <public_key_id> -a <card_id> -k alice/private.key"
            " -d email:alice_main@domain.com -d email:alice_reserve@domain.com\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kPublicKeyRevokeGlobal_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> publicKeyIdArg(cli::kPublicKeyId_ShortName, cli::kPublicKeyId_LongName,
                                                    cli::kPublicKeyId_Description, true, "",
                                                    cli::kPublicKeyId_TypeDesc);

        TCLAP::ValueArg<std::string> cardIdArg(cli::kCardId_ShortName, cli::kCardId_LongName, cli::kCardId_Description,
                                               true, "", cli::kCardId_TypeDesc);

        TCLAP::MultiArg<std::string> identitiesArg(cli::kIdentity_ShortName, cli::kIdentity_LongName,
                                                   cli::kGlobalIdentity_Description, true, cli::kIdentity_TypedDesc);

        TCLAP::MultiArg<std::string> validatedIdentityArg(
            cli::kValidatedIdentity_ShortName, cli::kValidatedIdentity_LongName,
            cli::kGlobalValidatedIdentity_Description, true, cli::kValidatedIdentity_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyArg(cli::kPrivateKey_ShortName, cli::kPrivateKey_LongName,
                                                   cli::kPrivateKey_Description, true, "", cli::kPrivateKey_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            cli::kPrivateKeyPassword_ShortName, cli::kPrivateKeyPassword_LongName, cli::kPrivateKeyPassword_Description,
            false, "", cli::kPrivateKeyPassword_TypeDesc);

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(privateKeyArg);
        cmd.xorAdd(validatedIdentityArg, identitiesArg);
        cmd.add(cardIdArg);
        cmd.add(publicKeyIdArg);
        cmd.parse(argc, argv);

        std::string pathPrivateKey = privateKeyArg.getValue();
        vcrypto::VirgilByteArray privateKey = wsdk::readPrivateKey(pathPrivateKey);
        vcrypto::VirgilByteArray privateKeyPassword;
        if (privateKeyPasswordArg.isSet()) {
            privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
        } else {
            privateKeyPassword = cli::setPrivateKeyPass(privateKey);
        }
        vsdk::Credentials credentials(privateKey, privateKeyPassword);

        cli::ConfigFile configFile = cli::readConfigFile();
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.getServiceUri());

        std::vector<vsdk::dto::ValidatedIdentity> validatedIdentities;
        if (validatedIdentityArg.isSet()) {
            std::vector<std::string> validatedIdentityFiles = validatedIdentityArg.getValue();
            for (const auto& validatedIdentityFile : validatedIdentityFiles) {
                vsdk::dto::ValidatedIdentity validatedIdentity = wsdk::readValidatedIdentity(validatedIdentityFile);
                validatedIdentities.push_back(validatedIdentity);
            }
        } else {
            // identitiesArg.isSet
            // identitiesArg = email:alice@domain.com, email:bob@domain.com
            std::vector<std::string> identitiesValue;
            for (auto&& identityArg : identitiesArg.getValue()) {
                auto identityPair = cli::parsePair(identityArg);
                std::string arg = "-d, --identity";
                cli::checkFormatIdentity(arg, identityPair.first);
                identitiesValue.push_back(identityPair.second);
            }

            // identitiesValue = alice@domain.com, bob@domain.com
            for (auto&& identityValue : identitiesValue) {
                auto validatedIdentity = getValidatedIdentity(verboseArg.isSet(), identityValue, servicesHub);
                validatedIdentities.push_back(validatedIdentity);
            }
        }

        servicesHub.publicKey().revoke(publicKeyIdArg.getValue(), validatedIdentities, cardIdArg.getValue(),
                                       credentials);

        if (verboseArg.isSet()) {
            std::string messageSuccess =
                "Global Virgil Card with public-key-id:" + publicKeyIdArg.getValue() + " has been revoked";
            std::cout << messageSuccess << std::endl;
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "public-key-revoke-global. Error: " << exception.error() << " for arg " << exception.argId()
                  << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "public-key-revoke-global. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

vsdk::dto::ValidatedIdentity getValidatedIdentity(const bool verbose, const std::string& identityValue,
                                                  vsdk::ServicesHub& servicesHub) {
    std::string actionId = servicesHub.identity().verify(identityValue, vsdk::dto::VerifiableIdentityType::Email);
    if (verbose) {
        std::cout << "Send confirmation-code to " << identityValue << std::endl;
    }

    std::cout << "Enter confirmation code which was sent on you identity - "
              << "email"
              << ":" << identityValue << std::endl;
    std::string confirmationCode = cli::inputShadow();

    if (verbose) {
        std::cout << "Confirme identity " << identityValue << std::endl;
    }

    vsdk::dto::ValidatedIdentity validatedIdentity = servicesHub.identity().confirm(actionId, confirmationCode);
    if (verbose) {
        std::cout << "An Identity "
                  << "email"
                  << ":" << identityValue << " is confirmed" << std::endl;
    }

    return validatedIdentity;
}
