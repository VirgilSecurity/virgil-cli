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

#include <cli/argument/ArgumentValueTextSource.h>


#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>

#include <cli/memory.h>

#include <stdexcept>

using cli::Crypto;
using cli::model::Password;
using cli::model::PrivateKey;
using cli::model::Card;
using cli::argument::ArgumentValueTextSource;
using cli::error::ArgumentParseError;

static constexpr const char kParseErrorFormat[] = "Invalid format. Can not import Virgil Card from the text: '%s'.";

void ArgumentValueTextSource::doInit(const ArgumentSource& argumentSource) {
    (void)argumentSource;
}

const char* ArgumentValueTextSource::doGetName() const {
    return "ArgumentValueTextSource";
}

std::unique_ptr<Password> ArgumentValueTextSource::doReadPassword(const ArgumentValue& argumentValue) const {
    return std::make_unique<Password>(Crypto::ByteUtils::stringToBytes(argumentValue.value()));
}

std::unique_ptr<PrivateKey> ArgumentValueTextSource::doReadPrivateKey(const ArgumentValue& argumentValue) const {
    return std::make_unique<PrivateKey>(Crypto::ByteUtils::stringToBytes(argumentValue.value()), Crypto::Bytes());
}

std::unique_ptr<Card> ArgumentValueTextSource::doReadCard(const ArgumentValue& argumentValue) const {
    try {
        return std::make_unique<Card>(Card::importFromString(argumentValue.value()));
    } catch (const std::exception& exception) {
        LOG(FATAL) << exception.what();
        throw ArgumentParseError(tfm::format(kParseErrorFormat, argumentValue.value()));
    }
}

std::unique_ptr<std::vector<Card>> ArgumentValueTextSource::doReadCards(
        const ArgumentValue& argumentValue) const {

    auto result = std::make_unique<std::vector<Card>>();
    std::istringstream input(argumentValue.value());
    std::string cardString;
    while (std::getline(input, cardString)) {
        try {
            result->push_back(Card::importFromString(cardString));
        } catch (const std::exception& exception) {
            LOG(FATAL) << exception.what();
            throw ArgumentParseError(tfm::format(kParseErrorFormat, cardString));
        }
    }
    return result;
}
