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

#include <cli/command/CardGetCommand.h>

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

using cli::Crypto;
using cli::command::CardGetCommand;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentImportance;
using cli::argument::ArgumentParseOptions;
using cli::error::ArgumentRuntimeError;
using cli::formatter::CardKeyValueFormatter;
using cli::formatter::CardRawFormatter;

using virgil::sdk::client::Client;
using virgil::sdk::client::ServiceConfig;
using virgil::sdk::client::CardValidator;
using ServiceCrypto = virgil::sdk::crypto::Crypto;

const char* CardGetCommand::doGetName() const {
    return arg::value::VIRGIL_COMMAND_CARD_GET;
}

const char* CardGetCommand::doGetUsage() const {
    return usage::VIRGIL_CARD_GET;
}

ArgumentParseOptions CardGetCommand::doGetArgumentParseOptions() const {
    return ArgumentParseOptions().disableOptionsFirst();
}

void CardGetCommand::doProcess() const {
    ULOG1(INFO) << "Read arguments.";
    auto input = getArgumentIO()->getInput(ArgumentImportance::Optional);
    auto output = getArgumentIO()->getOutputSink(ArgumentImportance::Optional);
    auto appAccessToken = getArgumentIO()->getAppAccessToken(ArgumentImportance::Required);

    ULOG1(INFO) << "Request card.";
    auto serviceConfig = ServiceConfig::createConfig(appAccessToken.stringValue());
    serviceConfig.cardValidator(std::make_unique<CardValidator>(std::make_shared<ServiceCrypto>()));
    Client client(std::move(serviceConfig));
    auto card = client.getCard(input.stringValue()).get();
    ULOG1(INFO) << "Write card to the output.";
    if (output.isConsoleOutput()) {
        output.write(CardKeyValueFormatter().format(card));
    } else {
        output.write(CardRawFormatter().format(card));
    }
}
