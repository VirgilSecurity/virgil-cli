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

#include <cli/argument/ArgumentValueFileSource.h>

#include <cli/model/FileDataSource.h>
#include <cli/model/FileDataSink.h>
#include <cli/model/KeyEncryptCredentials.h>
#include <cli/model/KeyDecryptCredentials.h>

#include <cli/api/api.h>
#include <cli/memory.h>
#include <cli/io/Logger.h>
#include <cli/io/Path.h>

#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/client/CardValidator.h>

using cli::Crypto;
using cli::argument::ArgumentValue;
using cli::argument::ArgumentValueFileSource;
using cli::model::KeyAlgorithm;
using cli::model::PublicKey;
using cli::model::PrivateKey;
using cli::model::Password;
using cli::model::Card;
using cli::model::FileDataSource;
using cli::model::FileDataSink;
using cli::model::ServiceConfig;
using cli::io::Path;

using ServiceCrypto = virgil::sdk::crypto::Crypto;
using ServiceCardValidator = virgil::sdk::client::CardValidator;

const char* ArgumentValueFileSource::doGetName() const {
    return "ArgumentValueFileSource";
}

void ArgumentValueFileSource::doInit(const ArgumentSource& argumentSource) {
    (void) argumentSource;
}

std::unique_ptr<Password> ArgumentValueFileSource::doReadPassword(const ArgumentValue& argumentValue) const {
    if (!existsLocally(argumentValue)) {
        return nullptr;
    }
    return std::make_unique<Password>(readLine(argumentValue));
}

std::unique_ptr<PublicKey> ArgumentValueFileSource::doReadPublicKey(const ArgumentValue& argumentValue) const {
    if (!existsLocally(argumentValue)) {
        return nullptr;
    }
    return std::make_unique<PublicKey>(readBytes(argumentValue), argumentValue.alias());
}

std::unique_ptr<PrivateKey> ArgumentValueFileSource::doReadPrivateKey(const ArgumentValue& argumentValue) const {
    if (!existsLocally(argumentValue)) {
        return nullptr;
    }
    return std::make_unique<PrivateKey>(readBytes(argumentValue), argumentValue.alias());
}

std::unique_ptr<std::vector<Card>> ArgumentValueFileSource::doReadCards(const ArgumentValue& argumentValue) const {
    if (!existsLocally(argumentValue)) {
        return nullptr;
    }
    auto result = std::make_unique<std::vector<Card>>();
    result->push_back(Card::importFromString(readText(argumentValue)));
    return result;
}

bool ArgumentValueFileSource::existsLocally(const ArgumentValue& argumentValue) {
    return Path::exists(argumentValue.value(), true);
}

Crypto::Text ArgumentValueFileSource::readLine(const ArgumentValue& argumentValue) {
    return FileDataSource(argumentValue.value()).readLine();
}

Crypto::Text ArgumentValueFileSource::readText(const ArgumentValue& argumentValue) {
    return FileDataSource(argumentValue.value()).readText();
}

Crypto::Bytes ArgumentValueFileSource::readBytes(const ArgumentValue& argumentValue) {
    return FileDataSource(argumentValue.value()).readAll();
}
