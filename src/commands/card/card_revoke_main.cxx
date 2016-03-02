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
#include <stdexcept>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/ServicesHub.h>

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
#define MAIN card_revoke_main
#endif

int MAIN(int argc, char **argv) {
    try {
        std::string description = "Revoke Virgil Card from the Virgil Public Key service.\n";

        std::vector <std::string> examples;
        examples.push_back(
                "Revoke Virgil Card with confirm identity:\n"
                "virgil card-revoke -a <card_id> -d email:user@domain.com -t <validation_token> "
                "-k <private_key>\n");

        examples.push_back(
                "Revoke Virgil Card with confirm identity:\n"
                "virgil card-revoke -a <card_id> -d email:user@domain.com "
                "-k <private_key>\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> cardIdArg("a", "card-id", "Virgil Card identifier",
                true, "", "arg");

        TCLAP::ValueArg<std::string> identityArg("d", "identity", "Identity user",
                true, "", "arg");

        TCLAP::ValueArg<std::string> validationTokenArg("t", "validation-token", "Validation token",
                false, "", "");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "private-key", "Private key",
                true, "", "file");

        TCLAP::ValueArg<std::string> privateKeyPassArg("p", "private-key-pass", "Private key pass",
                false, "", "arg");

        cmd.add(privateKeyPassArg);
        cmd.add(privateKeyArg);
        cmd.add(validationTokenArg);
        cmd.add(identityArg);
        cmd.add(cardIdArg);
        cmd.parse(argc, argv);

        vsdk::ServicesHub servicesHub(VIRGIL_ACCESS_TOKEN);

        std::string cardId = cardIdArg.getValue();

        auto identityPair = vcli::parsePair(identityArg.getValue());
        std::string userEmail = identityPair.second;

        std::string pathPrivateKey = privateKeyArg.getValue();
        vcrypto::VirgilByteArray privateKey = vcli::readFileBytes(pathPrivateKey);

        vcrypto::VirgilByteArray privateKeyPass = vcrypto::str2bytes(privateKeyPassArg.getValue());

        vsdk::Credentials credentials(privateKey, privateKeyPass);

        std::string messageSuccess = "Card with card-id " + cardIdArg.getValue() + " revoked.";
        if (validationTokenArg.isSet()) {
            std::string validationToken = validationTokenArg.getValue();
            vsdk::model::ValidatedIdentity validatedIdentity(validationToken, userEmail,
                    vsdk::model::IdentityType::Email);
            servicesHub.card().revoke(cardId, validatedIdentity, credentials);
            std::cout << messageSuccess << std::endl;
        } else {
            vsdk::model::Identity identity(userEmail, vsdk::model::IdentityType::Email);
            servicesHub.card().revoke(cardId, identity, credentials);
            std::cout << messageSuccess << std::endl;
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "card-revoke. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "card-revoke. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
