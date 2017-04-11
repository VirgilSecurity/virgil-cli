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

#include <cli/command/CardSearchCommand.h>

#include <cli/api/api.h>
#include <cli/crypto/Crypto.h>
#include <cli/io/Logger.h>
#include <cli/io/Path.h>
#include <cli/error/ArgumentError.h>
#include <cli/formatter/CardKeyValueFormatter.h>

#include <cli/memory.h>

#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/client/CardValidator.h>

#include <iostream>

using cli::Crypto;
using cli::command::CardSearchCommand;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentImportance;
using cli::argument::ArgumentParseOptions;
using cli::error::ArgumentRuntimeError;
using cli::model::Card;
using cli::model::CardScope;
using cli::model::card_scope_from;
using cli::model::FileDataSink;
using cli::io::Path;
using cli::formatter::CardKeyValueFormatter;

using virgil::sdk::client::Client;
using virgil::sdk::client::ServiceConfig;
using virgil::sdk::client::CardValidator;
using virgil::sdk::client::models::SearchCardsCriteria;
using ServiceCrypto = virgil::sdk::crypto::Crypto;

const char* CardSearchCommand::doGetName() const {
    return arg::value::VIRGIL_COMMAND_CARD_SEARCH;
}

const char* CardSearchCommand::doGetUsage() const {
    return usage::VIRGIL_CARD_SEARCH;
}

ArgumentParseOptions CardSearchCommand::doGetArgumentParseOptions() const {
    return ArgumentParseOptions().disableOptionsFirst();
}

static void purgeCardsToStandardOut(const std::vector<Card>& cards, bool noFormat) {
    for (const auto& card : cards) {
        ULOG1(INFO) << tfm::format("Write Virgil Card: %s:%s (%s).",
                card.identityType(), card.identity(), card.identifier());
        if (noFormat) {
            std::cout << card.exportAsString() << std::endl;
        } else {
            std::cout << std::endl << CardKeyValueFormatter().showBaseProperties().format(card);
        }
    }
}

static void purgeCardsToDir(const std::vector<Card>& cards, const std::string& outDir) {
    for (const auto& card : cards) {
        auto fileName = Path::joinPath(outDir, card.identifier() + ".vcard");
        ULOG1(INFO) << tfm::format("Write Virgil Card: %s:%s (%s), to the file '%s'.",
                card.identityType(), card.identity(), card.identifier(), fileName);
        FileDataSink fileDataSink(fileName);
        if (fileDataSink.isGood()) {
            fileDataSink.write(card.exportAsString());
        } else {
            ULOG(ERROR) << tfm::format("File '%s' was not written due to errors.", fileName);
        }
    }
}

static void purgeCards(const std::vector<Card>& cards, const std::string& outDir, bool noFormat) {
    if (outDir.empty()) {
        purgeCardsToStandardOut(cards, noFormat);
    } else if (!Path::createDir(outDir.c_str())) {
        throw ArgumentRuntimeError(tfm::format("Can not create output directory '%s'.", outDir));
    } else {
        purgeCardsToDir(cards, outDir);
    }

}

template<typename IterBegin, typename IterEnd>
static std::string format_list(IterBegin begin, IterEnd end) {
    if (begin == end) {
        return "{ }";
    }
    std::string result = "{ ";
    for (auto v = begin; v != end; ++v) {
        if (v != begin) {
            result += ", ";
        }
        result += *v;
    }
    result += " }";
    return result;
}

template<typename T>
std::string format_list(const std::vector<T>& v) {
    return format_list(v.cbegin(), v.cend());
}

void CardSearchCommand::doProcess() const {
    ULOG1(INFO) << "Read arguments.";
    auto output = getArgumentIO()->getOutput(ArgumentImportance::Optional);
    auto scope = getArgumentIO()->getCardScope(ArgumentImportance::Required);
    auto cardIdentityGroup = getArgumentIO()->getCardIdentityGroup(ArgumentImportance::Required);
    auto appAccessToken = getArgumentIO()->getAppAccessToken(ArgumentImportance::Required);
    auto noFormat = getArgumentIO()->isNoFormat();

    auto serviceConfig = ServiceConfig::createConfig(appAccessToken.stringValue());
    serviceConfig.cardValidator(std::make_unique<CardValidator>(std::make_shared<ServiceCrypto>()));
    Client client(std::move(serviceConfig));

    ULOG1(INFO) << "Start searching for Virgil Cards.";
    for (const auto& cardIdentity : cardIdentityGroup.identities()) {
        auto identityType = cardIdentity.first;
        auto identities = cardIdentity.second;
        ULOG1(INFO) << tfm::format("Search cards for identities: %s", format_list(identities));
        auto searchCriteria = SearchCardsCriteria::createCriteria(identities, card_scope_from(scope), identityType);
        auto cards = client.searchCards(searchCriteria).get();
        UVLOG(INFO, (cards.empty() ? 0 : 1))
                << tfm::format("Found %d Virgil Card(s) for identities: %s", cards.size(), format_list(identities));
        purgeCards(cards, output.stringValue(), noFormat);
    }
}
