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

#include <cli/argument/ArgumentValueVirgilSource.h>

#include <cli/argument/ArgumentImportance.h>
#include <cli/memory.h>
#include <cli/io/Logger.h>
#include <cli/api/api.h>
#include <cli/api/Configurations.h>
#include <cli/error/ArgumentError.h>

#include <virgil/sdk/VirgilSdkException.h>
#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/client/interfaces/ClientInterface.h>
#include <virgil/sdk/client/models/ClientCommon.h>
#include <virgil/sdk/client/models/SearchCardsCriteria.h>

#include <algorithm>
#include <iterator>

using cli::Configurations;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentValueVirgilSource;
using cli::argument::ArgumentImportance;
using cli::model::KeyAlgorithm;
using cli::model::PublicKey;
using cli::model::PrivateKey;
using cli::model::Password;
using cli::model::Card;
using cli::model::Password;
using cli::error::ArgumentFileNotFound;

using virgil::sdk::VirgilSdkException;
using virgil::sdk::client::Client;
using virgil::sdk::client::interfaces::ClientInterface;
using virgil::sdk::client::models::SearchCardsCriteria;
using virgil::sdk::client::models::CardScope;

ArgumentValueVirgilSource::ArgumentValueVirgilSource(ArgumentValueVirgilSource&&) = default;
ArgumentValueVirgilSource& ArgumentValueVirgilSource::operator=(ArgumentValueVirgilSource&&) = default;
ArgumentValueVirgilSource::~ArgumentValueVirgilSource() noexcept = default;

namespace cli { namespace argument {

struct ArgumentValueVirgilSource::Impl {
    std::string accessToken;
};

}}

ArgumentValueVirgilSource::ArgumentValueVirgilSource()
        : impl_(std::make_unique<ArgumentValueVirgilSource::Impl>()){
}

const char* ArgumentValueVirgilSource::doGetName() const {
    return "ArgumentValueVirgilSource";
}

void ArgumentValueVirgilSource::doInit(const ArgumentSource& argumentSource) {
    auto argument = argumentSource.read(arg::value::VIRGIL_CONFIG_APP_ACCESS_TOKEN, ArgumentImportance::Optional);
    if (argument.isValue() && argument.asValue().isString()) {
        impl_->accessToken = argument.asValue().value();
    }
}

std::unique_ptr<std::vector<Card>> ArgumentValueVirgilSource::doReadCards(const ArgumentValue& argumentValue) const {
    if(impl_->accessToken.empty()) {
        throw ArgumentFileNotFound(arg::value::VIRGIL_CONFIG_APP_ACCESS_TOKEN);
    }

    auto client = std::make_unique<Client>(impl_->accessToken);

    auto globalCardsFuture = client->searchCards(
            SearchCardsCriteria::createCriteria(CardScope::global, argumentValue.key(), { argumentValue.value() }));

    auto applicationCardsFuture = client->searchCards(
            SearchCardsCriteria::createCriteria(CardScope::application, argumentValue.key(), { argumentValue.value() }));

    try {
        ULOG1(INFO) << "Loading Virgil Cards...";
        auto&& globalCards = globalCardsFuture.get();
        ULOG1(INFO) << tfm::format("Found %d Virgil Cards in the global scope.", globalCards.size());
        auto&& applicationCards = applicationCardsFuture.get();
        ULOG1(INFO) << tfm::format("Found %d Virgil Cards in the application scope.", applicationCards.size());

        globalCards.insert(globalCards.end(),
                std::make_move_iterator(applicationCards.begin()), std::make_move_iterator(applicationCards.end()));

        return std::make_unique<std::vector<Card>>(std::move(globalCards));
    } catch (const VirgilSdkException& exception) {
        LOG(ERROR) << "Failed to load Virgil Cards." << exception.what();
        ULOG(ERROR) << "Failed to load Virgil Cards." << exception.condition().message();
        return nullptr;
    }
}
