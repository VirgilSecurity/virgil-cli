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

#include <cli/model/PrivateKey.h>

using cli::Crypto;
using cli::model::PublicKey;
using cli::model::PrivateKey;
using cli::model::SecureValue;

PublicKey PrivateKey::extractPublic() const {
    return PublicKey(Crypto::KeyPair::extractPublicKey(key(), password_.bytesValue()), identifier());
}

bool PrivateKey::isEncrypted() const {
    return Crypto::KeyPair::isPrivateKeyEncrypted(key());
}

void PrivateKey::setPassword(SecureValue keySecureValue) {
    password_ = std::move(keySecureValue);
}

SecureValue PrivateKey::password() const {
    return password_;
}

bool PrivateKey::checkPassword(const SecureValue& keySecureValue) const {
    return Crypto::KeyPair::checkPrivateKeyPassword(key(), keySecureValue.bytesValue());
}
bool PrivateKey::checkPassword() const {
    return Crypto::KeyPair::checkPrivateKeyPassword(key(), password_.bytesValue());
}
