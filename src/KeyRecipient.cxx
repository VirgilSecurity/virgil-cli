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

#include <cli/model/KeyRecipient.h>

#include <cli/crypto/Crypto.h>

#include <virgil/sdk/crypto/Crypto.h>

using cli::Crypto;
using cli::model::KeyRecipient;
using cli::loader::KeyLoader;
using cli::model::SecureKey;

using ServiceCrypto = virgil::sdk::crypto::Crypto;

static Crypto::Bytes computeRecipientIdentifier(
        const Crypto::Bytes& privateKey, const Crypto::Bytes& privateKeyPassword, const Crypto::Bytes& alias) {
    if (!alias.empty()) {
        return alias;
    }
    auto publicKey = Crypto::KeyPair::extractPublicKey(privateKey, privateKeyPassword);
    return ServiceCrypto().computeHash(Crypto::KeyPair::publicKeyToDER(publicKey), Crypto::HashAlgorithm::SHA256);
}


KeyRecipient::KeyRecipient(std::unique_ptr<KeyLoader> keyLoader) : keyLoader_(std::move(keyLoader)) {
}

void KeyRecipient::doAddSelfTo(Crypto::CipherBase& cipher,
        const virgil::sdk::client::interfaces::ClientInterface& serviceClient) const {
    for (const auto& publicKey : keyLoader_->loadKeys(serviceClient)) {
        cipher.addKeyRecipient(publicKey.identifier(), publicKey.key());
    }
}

void KeyRecipient::doDecrypt(Crypto::StreamCipher& cipher,
        Crypto::DataSource& source, Crypto::DataSink& sink, const SecureKey& keyPassword,
        const virgil::sdk::client::interfaces::ClientInterface& serviceClient) const {
    auto secureKeyList = keyLoader_->loadKeys(serviceClient);
    const auto& secureKey = secureKeyList.front();
    auto recipientIdentifier = computeRecipientIdentifier(secureKey.key(), keyPassword.key(), secureKey.identifier());
    cipher.decryptWithKey(source, sink, recipientIdentifier, secureKey.key(), keyPassword.key());
}
