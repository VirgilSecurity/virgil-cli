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

#include <cli/argument/ArgumentValueSource.h>

#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>

using cli::argument::ArgumentValueSource;
using cli::error::ArgumentValueSourceError;
using cli::model::PublicKey;
using cli::model::PrivateKey;
using cli::model::Password;
using cli::model::KeyAlgorithm;
using cli::model::Card;
using cli::model::ServiceConfig;
using cli::model::Token;

static constexpr const char kLogFormatMessage_ReadValueFromSource[] = "Try read %s from the source: %s.";
static constexpr const char kLogFormatMessage_ReadValueFailed[] = "Failed to read %s from the source: %s, try next.";
static constexpr const char kLogFormatMessage_ReadValueTotalFail[] = "Failed to read %s from any source.";

static constexpr const char kValueName_KeyAlgorithm[] = "key algorithm";
static constexpr const char kValueName_PublicKey[] = "public key";
static constexpr const char kValueName_PrivateKey[] = "private key";
static constexpr const char kValueName_Password[] = "password";
static constexpr const char kValueName_VirgilCards[] = "Virgil Cards";

namespace std {
    inline string to_string(const string& str) {
        return str;
    }
}

namespace inner {

template<typename T, typename V>
inline std::unique_ptr<T> not_null(std::unique_ptr<T> ptr, const V& value) {
    if (ptr) {
        return std::move(ptr);
    }
    throw ArgumentValueSourceError(std::to_string(value));
}

}

const char* ArgumentValueSource::getName() const {
    return doGetName();
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
        return this;
    }
}

std::unique_ptr<KeyAlgorithm> ArgumentValueSource::readKeyAlgorithm(const std::string& value) const {
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFromSource, kValueName_KeyAlgorithm, getName());
    return inner::not_null(doReadKeyAlgorithm(value), value);
}

std::unique_ptr<PublicKey> ArgumentValueSource::readPublicKey(const Token& token) const {
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFromSource, kValueName_PublicKey, getName());
    return inner::not_null(doReadPublicKey(token), token);
}

std::unique_ptr<PrivateKey> ArgumentValueSource::readPrivateKey(const std::string& value) const {
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFromSource, kValueName_PrivateKey, getName());
    return inner::not_null(doReadPrivateKey(value), value);
}

std::unique_ptr<PrivateKey> ArgumentValueSource::readPrivateKey(const Token& token) const {
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFromSource, kValueName_PrivateKey, getName());
    return inner::not_null(doReadPrivateKey(token), token);
}

std::unique_ptr<Password> ArgumentValueSource::readPassword(const std::string& value) const {
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFromSource, kValueName_Password, getName());
    return inner::not_null(doReadPassword(value), value);
}

std::unique_ptr<std::vector<Card>> ArgumentValueSource::readCards(const Token& token) const {
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFromSource, kValueName_VirgilCards, getName());
    return inner::not_null(doReadCards(token), token);
}

std::unique_ptr<KeyAlgorithm> ArgumentValueSource::doReadKeyAlgorithm(const std::string& value) const {
    if (nextSource_) {
        LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFailed, kValueName_KeyAlgorithm, getName());
        return nextSource_->readKeyAlgorithm(value);
    }
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueTotalFail, kValueName_KeyAlgorithm);
    return nullptr;
}

std::unique_ptr<PublicKey> ArgumentValueSource::doReadPublicKey(const Token& token) const {
    if (nextSource_) {
        LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFailed, kValueName_PublicKey, getName());
        return nextSource_->readPublicKey(token);
    }
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueTotalFail, kValueName_PublicKey);
    return nullptr;
}

std::unique_ptr<PrivateKey> ArgumentValueSource::doReadPrivateKey(const Token& token) const {
    if (nextSource_) {
        LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFailed, kValueName_PrivateKey, getName());
        return nextSource_->readPrivateKey(token);
    }
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueTotalFail, kValueName_PrivateKey);
    return nullptr;
}

std::unique_ptr<PrivateKey> ArgumentValueSource::doReadPrivateKey(const std::string& value) const {
    if (nextSource_) {
        LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFailed, kValueName_PrivateKey, getName());
        return nextSource_->readPrivateKey(value);
    }
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueTotalFail, kValueName_PrivateKey);
    return nullptr;
}

std::unique_ptr<Password> ArgumentValueSource::doReadPassword(const std::string& value) const {
    if (nextSource_) {
        LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFailed, kValueName_Password, getName());
        return nextSource_->readPassword(value);
    }
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueTotalFail, kValueName_Password);
    return nullptr;
}

std::unique_ptr<std::vector<Card>>
ArgumentValueSource::doReadCards(const Token& token) const {
    if (nextSource_) {
        LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueFailed, kValueName_VirgilCards, getName());
        return nextSource_->readCards(token);
    }
    LOG(INFO) << tfm::format(kLogFormatMessage_ReadValueTotalFail, kValueName_VirgilCards);
    return nullptr;
}
