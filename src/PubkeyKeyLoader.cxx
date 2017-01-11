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

#include <cli/loader/PubkeyKeyLoader.h>

#include <cli/crypto/Crypto.h>
#include <cli/logger/Logger.h>

#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/crypto/Crypto.h>

using cli::Crypto;
using cli::loader::PubkeyKeyLoader;
using cli::model::SecureKey;

using virgil::sdk::client::interfaces::ClientInterface;
using virgil::sdk::client::models::Card;

using ServiceCrypto = virgil::sdk::crypto::Crypto;

static  Crypto::Bytes computePublicKeyIdentifier(const Crypto::Bytes& publicKey, const Crypto::Text& alias) {
    if (!alias.empty()) {
        return Crypto::ByteUtils::stringToBytes(alias);
    }
    return ServiceCrypto().computeHash(Crypto::KeyPair::publicKeyToDER(publicKey), Crypto::HashAlgorithm::SHA256);
}

std::vector<SecureKey> PubkeyKeyLoader::doLoadKeys(const ClientInterface& serviceClient) const {
    auto publicKey = Crypto::FileDataSource(source()).readAll();
    auto publicKeyIdentifier = computePublicKeyIdentifier(publicKey, alias());
    std::vector<SecureKey> result;
    result.emplace_back(std::move(publicKeyIdentifier), std::move(publicKey));
    return result;
}
