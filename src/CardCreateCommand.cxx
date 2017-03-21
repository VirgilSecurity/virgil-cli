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

#include <cli/command/CardCreateCommand.h>

#include <cli/api/api.h>
#include <cli/crypto/Crypto.h>
#include <cli/io/Logger.h>
#include <cli/error/ArgumentError.h>
#include <cli/formatter/CardKeyValueFormatter.h>
#include <cli/formatter/CardRawFormatter.h>

#include <cli/memory.h>

#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/client/RequestSigner.h>
#include <virgil/sdk/client/CardValidator.h>
#include <virgil/sdk/client/models/interfaces/SignableRequestInterface.h>
#include <virgil/sdk/client/models/serialization/JsonSerializer.h>

using cli::Crypto;
using cli::command::CardCreateCommand;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentImportance;
using cli::argument::ArgumentParseOptions;
using cli::error::ArgumentRuntimeError;
using cli::error::ArgumentLogicError;
using cli::formatter::CardKeyValueFormatter;
using cli::formatter::CardRawFormatter;

using virgil::sdk::client::Client;
using virgil::sdk::client::ServiceConfig;
using virgil::sdk::client::CardValidator;
using virgil::sdk::client::RequestSigner;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::interfaces::SignableRequestInterface;
using virgil::sdk::client::models::serialization::JsonSerializer;
using ServiceCrypto = virgil::sdk::crypto::Crypto;

const char* CardCreateCommand::doGetName() const {
    return arg::value::VIRGIL_COMMAND_CARD_CREATE;
}

const char* CardCreateCommand::doGetUsage() const {
    return usage::VIRGIL_CARD_CREATE;
}

ArgumentParseOptions CardCreateCommand::doGetArgumentParseOptions() const {
    return ArgumentParseOptions().disableOptionsFirst();
}

void CardCreateCommand::doProcess() const {
    ULOG1(INFO) << "Read arguments.";
    auto output = getArgumentIO()->getOutputSink(ArgumentImportance::Optional);
    auto privateKey = getArgumentIO()->getPrivateKey(ArgumentImportance::Required);
    auto identity = getArgumentIO()->getCardIdentity(ArgumentImportance::Required);
    auto scope = getArgumentIO()->getCardScope(ArgumentImportance::Optional);
    auto data = getArgumentIO()->getCardData(ArgumentImportance::Optional);
    auto info = getArgumentIO()->getCardInfo(ArgumentImportance::Optional);
    auto appAccessToken = getArgumentIO()->getAppAccessToken(ArgumentImportance::Required);

    ULOG1(INFO) << "Create request for card creation.";
    auto createCardRequest = CreateCardRequest::createRequest(
            identity.value(), identity.type(), privateKey.extractPublic().key(),
            data, info.device(), info.deviceName());

    ULOG1(INFO) << "Sign request with given private key.";
    auto crypto = std::make_shared<ServiceCrypto>();
    RequestSigner signer(crypto);
    auto selfPrivateKey = crypto->importPrivateKey(privateKey.key(), privateKey.password().stringValue());
    signer.selfSign(createCardRequest, selfPrivateKey);

    if (scope == arg::value::VIRGIL_CARD_CREATE_SCOPE_APPLICATION) {
        ULOG1(INFO) << "Read application credentials (self sign).";
        auto appCredentials = getArgumentIO()->getAppCredentials(ArgumentImportance::Required);
        ULOG1(INFO) << "Import application private key.";
        auto appPrivateKey = crypto->importPrivateKey(
                appCredentials.appPrivateKey().key(), appCredentials.appPrivateKey().password().stringValue());
        ULOG1(INFO) << "Sign request with application private key (authority sign).";
        signer.authoritySign(createCardRequest, appCredentials.appId().stringValue(), appPrivateKey);
    } else if (scope == arg::value::VIRGIL_CARD_CREATE_SCOPE_GLOBAL) {
        throw ArgumentRuntimeError("Card creation with GLOBAL scope is not supported yet.");
    } else {
        throw ArgumentLogicError("Undefined card scope. Validation must fail first.");
    }

#if ELPP_DEBUG_LOG
    for (const auto& signature : createCardRequest.signatures()) {
        DLOG(INFO) << "Added signature with fingerprint:" << signature.first;
    }
#endif

    ULOG1(INFO) << "Request card creation.";
    LOG(INFO) << "Card create request:\n"
              << JsonSerializer<SignableRequestInterface>::toJson(createCardRequest);
    auto serviceConfig = ServiceConfig::createConfig(appAccessToken.stringValue());
    serviceConfig.cardValidator(std::make_unique<CardValidator>(crypto));
    Client client(std::move(serviceConfig));
    auto card = client.createCard(createCardRequest).get();
    ULOG1(INFO) << "Write card to the output.";
    if (output.isConsoleOutput()) {
        output.write(CardKeyValueFormatter().format(card));
    } else {
        output.write(CardRawFormatter().format(card));
    }
}
