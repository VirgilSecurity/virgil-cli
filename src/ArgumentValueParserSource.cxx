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

#include <cli/argument/ArgumentValueParserSource.h>

#include <cli/memory.h>
#include <cli/crypto/Crypto.h>

using cli::Crypto;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentValueParserSource;
using cli::model::KeyAlgorithm;
using cli::model::PublicKey;
using cli::model::PrivateKey;
using cli::model::Password;
using cli::model::Card;

const char* ArgumentValueParserSource::doGetName() const {
    return "ArgumentValueParserSource";
}

void ArgumentValueParserSource::doInit(const ArgumentSource& argumentSource) {
    (void)argumentSource;
}

std::unique_ptr<KeyAlgorithm> ArgumentValueParserSource::doReadKeyAlgorithm(const std::string& value) const {
    return std::make_unique<KeyAlgorithm>(KeyAlgorithm::from(value));
}

std::unique_ptr<Password> ArgumentValueParserSource::doReadPassword(const std::string& value) const {
    return std::make_unique<Password>(Crypto::ByteUtils::stringToBytes(value));
}

std::unique_ptr<PublicKey> ArgumentValueParserSource::doReadPublicKey(const model::Token& token) const {
    return std::make_unique<PublicKey>(Crypto::Base64::decode(token.value()), token.alias());
}

std::unique_ptr<PrivateKey> ArgumentValueParserSource::doReadPrivateKey(const model::Token& token) const {
    return std::make_unique<PrivateKey>(Crypto::Base64::decode(token.value()), token.alias());
}
