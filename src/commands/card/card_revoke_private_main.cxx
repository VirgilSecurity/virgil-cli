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

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/ServicesHub.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>
#include <cli/wrapper/sdk/PrivateKey.h>
#include <cli/wrapper/sdk/ValidatedIdentity.h>
#include <cli/InputShadow.h>

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace wsdk = cli::wrapper::sdk;

int card_revoke_private_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{
            "1. Revoke a Private Virgil Card with a confirmed identity:\n"
            "\tvirgil card-revoke-private -a <card_id> -f private-validated-identities.file "
            "-k private.key\n\n",

            "2. Revoke a Private Virgil Card with a unconfirmed identity:\n"
            "\tvirgil card-revoke-private -a <card_id> -k private.key\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kCardRevokePrivate_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> cardIdArg(cli::kCardId_ShortName, cli::kCardId_LongName, cli::kCardId_Description,
                                               true, "", cli::kCardId_TypeDesc);

        TCLAP::ValueArg<std::string> validatedIdentityArg(
            cli::kValidatedIdentity_ShortName, cli::kValidatedIdentity_LongName, cli::kPrivateIdentity_Description,
            false, "", cli::kValidatedIdentity_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyArg(cli::kPrivateKey_ShortName, cli::kPrivateKey_LongName,
                                                   cli::kPrivateKey_Description, true, "", cli::kPrivateKey_TypeDesc);

        TCLAP::ValueArg<std::string> privateKeyPasswordArg(
            cli::kPrivateKeyPassword_ShortName, cli::kPrivateKeyPassword_LongName, cli::kPrivateKeyPassword_Description,
            false, "", cli::kPrivateKeyPassword_TypeDesc);

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(privateKeyPasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(validatedIdentityArg);
        cmd.add(cardIdArg);
        cmd.parse(argc, argv);

        cli::ConfigFile configFile = cli::readConfigFile();
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.getServiceUri());

        std::string cardId = cardIdArg.getValue();

        std::string pathPrivateKey = privateKeyArg.getValue();
        vcrypto::VirgilByteArray privateKey = wsdk::readPrivateKey(pathPrivateKey);
        vcrypto::VirgilByteArray privateKeyPassword;
        if (privateKeyPasswordArg.isSet()) {
            privateKeyPassword = vcrypto::str2bytes(privateKeyPasswordArg.getValue());
        } else {
            privateKeyPassword = cli::setPrivateKeyPass(privateKey);
        }
        vsdk::Credentials credentials(privateKey, privateKeyPassword);

        std::string messageSuccess = "Card with card-id " + cardIdArg.getValue() + " revoked.";
        if (validatedIdentityArg.isSet()) {
            vsdk::dto::ValidatedIdentity validatedIdentity =
                wsdk::readValidatedIdentity(validatedIdentityArg.getValue());

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
        std::cerr << "card-revoke-private. Error: " << exception.error() << " for arg " << exception.argId()
                  << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "card-revoke-private. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
