/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

#include <cli/command/CardRevokeCommand.h>

#include <cli/api/api.h>
#include <cli/crypto/Crypto.h>
#include <cli/io/Logger.h>
#include <cli/error/ArgumentError.h>

#include <cli/memory.h>

#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/client/RequestSigner.h>
#include <virgil/sdk/client/CardValidator.h>

using cli::Crypto;
using cli::command::CardRevokeCommand;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentImportance;
using cli::argument::ArgumentParseOptions;
using cli::error::ArgumentRuntimeError;
using cli::error::ArgumentInvalidKey;
using cli::model::CardScope;

using virgil::sdk::client::Client;
using virgil::sdk::client::ServiceConfig;
using virgil::sdk::client::CardValidator;
using virgil::sdk::client::RequestSigner;
using virgil::sdk::client::models::requests::RevokeCardRequest;
using ServiceCrypto = virgil::sdk::crypto::Crypto;

const char* CardRevokeCommand::doGetName() const {
    return arg::value::VIRGIL_COMMAND_CARD_REVOKE;
}

const char* CardRevokeCommand::doGetUsage() const {
    return usage::VIRGIL_CARD_REVOKE;
}

ArgumentParseOptions CardRevokeCommand::doGetArgumentParseOptions() const {
    return ArgumentParseOptions().disableOptionsFirst();
}

void CardRevokeCommand::doProcess() const {
    ULOG1(INFO) << "Read arguments.";
    auto card = getArgumentIO()->getCardFromInput(ArgumentImportance::Required);
    auto reason = getArgumentIO()->getCardRevokeReason(ArgumentImportance::Required);
    auto appAccessToken = getArgumentIO()->getAppAccessToken(ArgumentImportance::Required);

    ULOG1(INFO) << "Create request for card revocation.";
    auto revokeCardRequest = RevokeCardRequest::createRequest(card.identifier(), reason);

    ULOG1(INFO) << "Sign request with given private key.";
    auto crypto = std::make_shared<ServiceCrypto>();
    RequestSigner signer(crypto);

    switch (card.scope()) {
        case CardScope::application: {
            ULOG1(INFO) << "Read application credentials (self sign).";
            auto appCredentials = getArgumentIO()->getAppCredentials(ArgumentImportance::Required);
            ULOG1(INFO) << "Import application private key.";
            auto appPrivateKey = crypto->importPrivateKey(
                    appCredentials.appPrivateKey().key(), appCredentials.appPrivateKey().password().stringValue());
            ULOG1(INFO) << "Sign request with application private key (authority sign).";
            signer.authoritySign(revokeCardRequest, appCredentials.appId().stringValue(), appPrivateKey);
        }
        break;
        case CardScope::global: {
            throw ArgumentRuntimeError("Card revocation with GLOBAL scope is not supported yet.");
        }
    }

    ULOG1(INFO) << "Request card revocation.";
    auto serviceConfig = ServiceConfig::createConfig(appAccessToken.stringValue());
    serviceConfig.cardValidator(std::make_unique<CardValidator>(crypto));
    Client client(std::move(serviceConfig));
    client.revokeCard(revokeCardRequest).get();
    ULOG1(INFO) << tfm::format("Card with id '%s' was revoked.", card.identifier());
}
