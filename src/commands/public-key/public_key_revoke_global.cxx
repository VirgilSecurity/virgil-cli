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
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include <tclap/CmdLine.h>

#include <virgil/sdk/ServicesHub.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;
namespace vcli = virgil::cli;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN public_key_revoke_global_main
#endif

static vsdk::dto::ValidatedIdentity getValidatedIdentity(const bool verbose, const std::string& identityValue,
                                                         vsdk::ServicesHub& servicesHub);

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Revoke a chain of Global Virgil Cards connected by public-key-id from "
                                  "Virgil Keys Service.\n";

        std::vector<std::string> examples;
        examples.push_back("Revoke a chain of Global Virgil Cards by public-key-id from Virgil Keys Service:\n"
                           "virgil public-key-revoke-global -e <public_key_id> -a <card_id> -k alice/private.key"
                           " -f alice/validated-identity-main.txt -f alice/validated-identity-reserve.txt\n\n");

        examples.push_back("Revoke a chain of Global Virgil Cards by public-key-id from Virgil Keys Service, "
                           "with confirming of identity:\n"
                           "virgil public-key-revoke-global -e <public_key_id> -a <card_id> -k alice/private.key"
                           " -d email:alice_main@domain.com -d email:alice_reserve@domain.com\n\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> publicKeyIdArg("e", "public-key-id", "Public Key identifier\n", true, "", "arg");

        TCLAP::ValueArg<std::string> cardIdArg("a", "card-id", "Global Virgil Card identifier", true, "", "arg");

        TCLAP::MultiArg<std::string> identitiesArg(
            "d", "identity", "Identity user, for example: -d email:alice@domain.com", true, "arg");

        TCLAP::MultiArg<std::string> validatedIdentityArg(
            "f", "validated-identity", "Validated Identity, see 'virgil identity-confirm-global'", true, "file");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "key", "Private key", true, "", "file");

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            "p", "private-key-password", "Password to be used for Private Key encryption.", false, "", "arg");

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Show detailed information", false);

        cmd.add(verboseArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(privateKeyArg);
        cmd.xorAdd(validatedIdentityArg, identitiesArg);
        cmd.add(cardIdArg);
        cmd.add(publicKeyIdArg);
        cmd.parse(argc, argv);

        std::string pathPrivateKey = privateKeyArg.getValue();
        vcrypto::VirgilByteArray privateKey = vcli::readPrivateKey(pathPrivateKey);
        vcrypto::VirgilByteArray privateKeyPassword;
        if (privateKeyPasswordArg.isSet()) {
            privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
        } else {
            privateKeyPassword = vcli::setPrivateKeyPass(privateKey);
        }
        vsdk::Credentials credentials(privateKey, privateKeyPassword);

        vcli::ConfigFile configFile = vcli::readConfigFile(verboseArg.isSet());
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.serviceUri);

        std::vector<vsdk::dto::ValidatedIdentity> validatedIdentities;
        if (validatedIdentityArg.isSet()) {
            std::vector<std::string> validatedIdentityFiles = validatedIdentityArg.getValue();
            for (const auto& validatedIdentityFile : validatedIdentityFiles) {
                vsdk::dto::ValidatedIdentity validatedIdentity = vcli::readValidateIdentity(validatedIdentityFile);
                validatedIdentities.push_back(validatedIdentity);
            }
        } else {
            // identitiesArg.isSet
            // identitiesArg = email:alice@domain.com, email:bob@domain.com
            std::vector<std::string> identitiesValue;
            for (auto&& identityArg : identitiesArg.getValue()) {
                auto identityPair = vcli::parsePair(identityArg);
                std::string arg = "-d, --identity";
                vcli::checkFormatIdentity(arg, identityPair.first);
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
    std::string confirmationCode = vcli::inputShadow();

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
