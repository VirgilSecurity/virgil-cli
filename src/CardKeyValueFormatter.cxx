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

#include <cli/formatter/CardKeyValueFormatter.h>

#include <cli/crypto/Crypto.h>
#include <cli/io/Logger.h>

using cli::formatter::KeyValueFormatter;
using cli::formatter::CardKeyValueFormatter;

using cli::model::Card;
using cli::model::CardProperty;

static void add(KeyValueFormatter::Container& values, const std::string& key, const std::string& value) {
    values.emplace_back(key, value);
}

std::string CardKeyValueFormatter::doFormat(const model::Card& card) const {
    KeyValueFormatter::Container values;

    if (hasProperty(CardProperty::Identifier)) {
        add(values, "id", card.identifier());
    }
    if (hasProperty(CardProperty::Identity)) {
        add(values, "identity", card.identity());
    }
    if (hasProperty(CardProperty::IdentityType)) {
        add(values, "identity type", card.identityType());
    }
    if (hasProperty(CardProperty::Scope)) {
        add(values, "scope", std::to_string(card.scope()));
    }
    if (hasProperty(CardProperty::Version)) {
        add(values, "version", card.cardVersion());
    }
    if (hasProperty(CardProperty::PublicKey)) {
        add(values, "public key",
                Crypto::ByteUtils::bytesToString(Crypto::KeyPair::publicKeyToPEM(card.publicKeyData())));
    }
    if (hasProperty(CardProperty::Data)) {
        for (auto data : card.data()) {
            add(values, tfm::format("data (%s)", data.first), data.second);
        }
    }
    if (hasProperty(CardProperty::Info)) {
        for (auto info : card.info()) {
            add(values, tfm::format("info (%s)", info.first), info.second);
        }
    }
    if (hasProperty(CardProperty::Signatures)) {
        for (auto signature : card.cardResponse().signatures()) {
            add(values, tfm::format("signature (%s)", signature.first),
                    Crypto::ByteUtils::bytesToHex(signature.second));
        }
    }

    return formatter_.format(values);
}

