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

#include <cli/formatter/CardRawFormatter.h>

#include <cli/crypto/Crypto.h>

#include <sstream>

using cli::Crypto;
using cli::formatter::CardRawFormatter;
using cli::model::CardProperty;

std::string CardRawFormatter::doFormat(const model::Card& card) const {
    std::ostringstream output;

    if (hasProperty(CardProperty::Identifier)) {
        output << card.identifier() << std::endl;
    }
    if (hasProperty(CardProperty::Identity)) {
        output << card.identity() << std::endl;
    }
    if (hasProperty(CardProperty::IdentityType)) {
        output << card.identityType() << std::endl;
    }
    if (hasProperty(CardProperty::Scope)) {
        output << std::to_string(card.scope()) << std::endl;
    }
    if (hasProperty(CardProperty::Version)) {
        output << card.cardVersion() << std::endl;
    }
    if (hasProperty(CardProperty::PublicKey)) {
        output << Crypto::ByteUtils::bytesToString(Crypto::KeyPair::publicKeyToPEM(card.publicKeyData())) << std::endl;
    }
    if (hasProperty(CardProperty::Data)) {
        for (auto data : card.data()) {
            output << data.first << " -> " << data.second << std::endl;
        }
    }
    if (hasProperty(CardProperty::Info)) {
        for (auto info : card.info()) {
            output << info.first << " -> " << info.second << std::endl;
        }
    }
    if (hasProperty(CardProperty::Signatures)) {
        for (auto signature : card.cardResponse().signatures()) {
            output << signature.first << " -> " << Crypto::ByteUtils::bytesToHex(signature.second) << std::endl;
        }
    }

    return output.str();
}
