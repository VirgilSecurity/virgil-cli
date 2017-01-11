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

#include <cli/loader/EmailKeyLoader.h>

#include <cli/api/api.h>
#include <cli/crypto/Crypto.h>
#include <cli/error/ArgumentError.h>

#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/client/models/SearchCardsCriteria.h>
#include <virgil/sdk/crypto/Crypto.h>

using cli::Crypto;
using cli::loader::EmailKeyLoader;
using cli::model::PublicKey;
using cli::error::ArgumentRecipientNotFound;

using virgil::sdk::client::interfaces::ClientInterface;
using virgil::sdk::client::models::SearchCardsCriteria;
using virgil::sdk::client::models::CardScope;
using virgil::sdk::client::models::Card;
using ServiceCrypto = virgil::sdk::crypto::Crypto;

std::vector<PublicKey> EmailKeyLoader::doLoadKeys(const ClientInterface& serviceClient) const {
    auto criteria = SearchCardsCriteria::createCriteria(
            CardScope::application, arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_EMAIL, { source() });
    auto future = serviceClient.searchCards(criteria);
    auto cards = future.get();
    if (cards.empty()) {
        throw ArgumentRecipientNotFound(arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_EMAIL, source());
    }
    std::vector<PublicKey> result;
    for (const auto& card : cards) {
        result.emplace_back(Crypto::ByteUtils::stringToBytes(card.identifier()), card.publicKeyData());
    }
    return result;
}
