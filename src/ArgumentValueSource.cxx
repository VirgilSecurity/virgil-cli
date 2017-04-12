/**
 * Copyright (C) 2015-2017 Virgil Security Inc.
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

#include <cli/argument/ArgumentValueSource.h>

#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>
#include <cli/types/EnumHelper.h>

using cli::argument::ArgumentValueSource;
using cli::argument::ArgumentSourceType;
using cli::error::ArgumentValueSourceError;
using cli::model::PublicKey;
using cli::model::PrivateKey;
using cli::model::Password;
using cli::model::KeyAlgorithm;
using cli::model::Card;
using cli::model::ServiceConfig;
using cli::model::EncryptCredentials;
using cli::model::DecryptCredentials;
using cli::model::HashAlgorithm;

static constexpr const char kLogFormatMessage_ReadValueSuccess[] = "Read '%s' succeed from the source: '%s'.";
static constexpr const char kLogFormatMessage_ReadValueFailed[] = "Read '%s' failed from the source: '%s'.";
static constexpr const char kLogFormatMessage_ReadValueTotalFail[] = "Read '%s' failed from any source.";

static constexpr const char kValueName_KeyAlgorithm[] = "Key Algorithm";
static constexpr const char kValueName_PublicKey[] = "Public Key";
static constexpr const char kValueName_PrivateKey[] = "Private Key";
static constexpr const char kValueName_Password[] = "Password";
static constexpr const char kValueName_VirgilCards[] = "Virgil Card(s)";
static constexpr const char kValueName_HashAlgorithm[] = "Hash Algorithm";

#define FOR_EACH_SOURCE(func, param, valueName) \
do { \
    for (auto source = this; source != nullptr; source = source->nextSource_.get()) { \
        if (!cli::types::hasFlag(source->getType(), useSourceTypes_)) { \
            continue; \
        } \
        auto value = source->func(param); \
        if (value) { \
            LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueSuccess, valueName, source->getName()); \
            return std::move(*value); \
        } else { \
            LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFailed, valueName, source->getName()); \
        } \
    } \
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueTotalFail, valueName); \
    throw ArgumentValueSourceError(std::to_string(argumentValue)); \
} while(false)

#define CAN_NOT_HANDLE(param) \
do { \
    (void)param; \
    return nullptr; \
} while(false)

const char* ArgumentValueSource::getName() const {
    return doGetName();
}

ArgumentSourceType ArgumentValueSource::getType() const {
    return doGetType();
}

void ArgumentValueSource::init(const ArgumentSource& argumentSource) {
    LOG(INFO) << "Initialize argument value sources.";
    for (auto source = this; source != nullptr; source = source->nextSource_.get()) {
        LOG(INFO) << tfm::format("Initialize argument value source: %s.", source->getName());
        source->doInit(argumentSource);
    }
}

ArgumentValueSource* ArgumentValueSource::appendSource(std::shared_ptr<ArgumentValueSource> source) {
    if (nextSource_) {
        return nextSource_->appendSource(std::move(source));
    } else {
        LOG(INFO) << tfm::format("Append argument value source: %s->%s.", getName(), source->getName());
        nextSource_ = std::move(source);
        return nextSource_.get();
    }
}

KeyAlgorithm ArgumentValueSource::readKeyAlgorithm(const ArgumentValue& argumentValue) const {
    FOR_EACH_SOURCE(doReadKeyAlgorithm, argumentValue, kValueName_KeyAlgorithm);
}

Password ArgumentValueSource::readPassword(const ArgumentValue& argumentValue) const {
    FOR_EACH_SOURCE(doReadPassword, argumentValue, kValueName_Password);
}

PublicKey ArgumentValueSource::readPublicKey(const ArgumentValue& argumentValue) const {
    FOR_EACH_SOURCE(doReadPublicKey, argumentValue, kValueName_PublicKey);
}

PrivateKey ArgumentValueSource::readPrivateKey(const ArgumentValue& argumentValue) const {
    FOR_EACH_SOURCE(doReadPrivateKey, argumentValue, kValueName_PrivateKey);
}

std::vector<Card> ArgumentValueSource::readCards(const ArgumentValue& argumentValue) const {
    FOR_EACH_SOURCE(doReadCards, argumentValue, kValueName_VirgilCards);
}

Card ArgumentValueSource::readCard(const ArgumentValue& argumentValue) const {
    FOR_EACH_SOURCE(doReadCard, argumentValue, kValueName_VirgilCards);
}

HashAlgorithm ArgumentValueSource::readHashAlgorithm(const ArgumentValue& argumentValue) const {
    FOR_EACH_SOURCE(doReadHashAlgorithm, argumentValue, kValueName_HashAlgorithm);
}

void ArgumentValueSource::resetFilter(const std::vector<ArgumentSourceType>& useSourceTypes) {
    useSourceTypes_ = 0;
    for (auto sourceType : useSourceTypes) {
        cli::types::addFlag(sourceType, &useSourceTypes_);
    }
}

std::unique_ptr<KeyAlgorithm> ArgumentValueSource::doReadKeyAlgorithm(const ArgumentValue& argumentValue) const {
    CAN_NOT_HANDLE(argumentValue);
}

std::unique_ptr<Password> ArgumentValueSource::doReadPassword(const ArgumentValue& argumentValue) const {
    CAN_NOT_HANDLE(argumentValue);
}

std::unique_ptr<PublicKey> ArgumentValueSource::doReadPublicKey(const ArgumentValue& argumentValue) const {
    CAN_NOT_HANDLE(argumentValue);
}

std::unique_ptr<PrivateKey> ArgumentValueSource::doReadPrivateKey(const ArgumentValue& argumentValue) const {
    CAN_NOT_HANDLE(argumentValue);
}

std::unique_ptr<std::vector<Card>> ArgumentValueSource::doReadCards(const ArgumentValue& argumentValue) const {
    CAN_NOT_HANDLE(argumentValue);
}

std::unique_ptr<Card> ArgumentValueSource::doReadCard(const ArgumentValue& argumentValue) const {
    CAN_NOT_HANDLE(argumentValue);
}

std::unique_ptr<HashAlgorithm> ArgumentValueSource::doReadHashAlgorithm(const ArgumentValue& argumentValue) const {
    CAN_NOT_HANDLE(argumentValue);
}
