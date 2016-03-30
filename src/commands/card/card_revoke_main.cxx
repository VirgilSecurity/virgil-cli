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

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Revoke Virgil Card from the Virgil Public Key service.\n";

        std::vector<std::string> examples;
        examples.push_back("Revoke Virgil Card with a confirmed identity:\n"
                           "virgil card-revoke -a <card_id> -f alice/validated-identities.file "
                           "-k alice/private.key\n");

        examples.push_back("Revoke Virgil Card with a confirmed identity:\n"
                           "virgil card-revoke -a <card_id> -k alice/private.key\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> cardIdArg("a", "card-id", "virgil Card identifier", true, "", "arg");

        TCLAP::ValueArg<std::string> validatedIdentityArg("f", "validated-identity", "Validated identity", false, "",
                                                          "file");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "key", "Private key", true, "", "file");

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            "p", "private-key-password", "Password to be used for Private Key encryption.", false, "", "arg");

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Show detailed information", false);

        cmd.add(verboseArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(validatedIdentityArg);
        cmd.add(cardIdArg);
        cmd.parse(argc, argv);

        vsdk::ServicesHub servicesHub(VIRGIL_ACCESS_TOKEN);

        std::string cardId = cardIdArg.getValue();

        std::string pathPrivateKey = privateKeyArg.getValue();
        vcrypto::VirgilByteArray privateKey = vcli::readPrivateKey(pathPrivateKey);
        vcrypto::VirgilByteArray privateKeyPassword;
        if (privateKeyPasswordArg.isSet()) {
            privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
        } else {
            privateKeyPassword = vcli::setPrivateKeyPass(privateKey);
        }
        vsdk::Credentials credentials(privateKey, privateKeyPassword);

        std::string messageSuccess = "Card with card-id " + cardIdArg.getValue() + " revoked.";
        if (validatedIdentityArg.isSet()) {
            vsdk::dto::ValidatedIdentity validatedIdentity =
                vcli::readValidateIdentity(validatedIdentityArg.getValue());

            servicesHub.card().revoke(cardId, validatedIdentity, credentials);
            if (verboseArg.isSet()) {
                std::cout << messageSuccess << std::endl;
            }
        } else {
            auto card = servicesHub.card().get(cardId);
            vsdk::dto::Identity identity(card.getCardIdentity().getValue(), card.getCardIdentity().getType());
            servicesHub.card().revoke(cardId, identity, credentials);
            if (verboseArg.isSet()) {
                std::cout << messageSuccess << std::endl;
            }
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
