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
#define MAIN public_key_revoke_main
#endif

static void checkFormatRecipientArg(const std::string& type);


int MAIN(int argc, char **argv) {
    try {
        std::string description =
                "Revoke a chain of cards with (un)confirmed identities connected by public-key-id from "
                "Virgil Keys Service.\n";

        std::vector <std::string> examples;
        examples.push_back(
                "Revoke a chain of cards with confirmed identities connected by public-key-id from "
                "Virgil Keys Service:\n"
                "virgil public-key-revoke -e <public_key_id> -a <card_id> -k <private_key>"
                " -f <validated-identities-file>");

        examples.push_back(
                "Revoke a chain of cards with confirmed identities connected by public-key-id from "
                "Virgil Keys Service:\n"
                "virgil public-key-revoke -e <public_key_id> -a <card_id> -k <private_key>"
                " -z <identities-file>");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> publicKeyIdArg("e", "public-key-id", "Public Key identifier\n",
                true, "", "arg");

        TCLAP::ValueArg<std::string> cardIdArg("a", "card-id", "Virgil Card identifier",
                true, "", "arg");

        TCLAP::MultiArg<std::string> identityArg("d", "identity", "Identity user",
                true, "arg");

        TCLAP::MultiArg<std::string> validatedIdentityArg("f", "validated-identities", "ValidatedIdentity",
                true, "file");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "private-key", "Private key",
                true, "", "file");

        TCLAP::ValueArg<std::string> privateKeyPassArg("p", "private-pwd", "Private key pass",
                false, "", "arg");

        cmd.add(privateKeyPassArg);
        cmd.add(privateKeyArg);
        cmd.xorAdd(validatedIdentityArg, identityArg);
        cmd.add(cardIdArg);
        cmd.add(publicKeyIdArg);
        cmd.parse(argc, argv);

        std::string pathPrivateKey = privateKeyArg.getValue();
        vcrypto::VirgilByteArray privateKey = vcli::readFileBytes(pathPrivateKey);

        vcrypto::VirgilByteArray privateKeyPass = vcrypto::str2bytes(privateKeyPassArg.getValue());
        vsdk::Credentials credentials(privateKey, privateKeyPass);

        vsdk::ServicesHub servicesHub(VIRGIL_ACCESS_TOKEN);

        if (validatedIdentityArg.isSet()) {
            std::vector<vsdk::model::ValidatedIdentity> validatedIdentities;
            std::vector<std::string> validatedIdentityFiles = validatedIdentityArg.getValue();
            for(const auto& validatedIdentityFile : validatedIdentityFiles) {
                vsdk::model::ValidatedIdentity validatedIdentity = vcli::readValidateIdentity(validatedIdentityFile);
                validatedIdentities.push_back(validatedIdentity);
            }

            servicesHub.publicKey().revoke(publicKeyIdArg.getValue(), validatedIdentities, cardIdArg.getValue(),
                    credentials);
        } else {
            // identityArg.isSet
            std::vector<std::string> identitiesStr = identityArg.getValue();
            std::vector<vsdk::model::Identity> identities;
            for(const auto& identityStr : identitiesStr) {
                auto identityPair = vcli::parsePair(identityStr);
                std::string recipientType = identityPair.first;
                std::string recipientValue = identityPair.second;

                checkFormatRecipientArg(recipientType);

                vsdk::model::IdentityType identityType = vsdk::model::fromString(recipientType);
                vsdk::model::Identity identity(recipientValue, identityType);

                identities.push_back(identity);
            }

            servicesHub.publicKey().revokeNotValid(publicKeyIdArg.getValue(), identities, cardIdArg.getValue(),
                    credentials);
        }


    } catch (TCLAP::ArgException& exception) {
        std::cerr << "public-key-revoke. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "public-key-revoke. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void checkFormatRecipientArg(const std::string& type) {
    if (type != "email") {
        throw std::invalid_argument(
                    "invalid type format: " + type + ". Expected format: '<key>:<value>'. "
                                                     "Where <key> = [email]");
    }
}
