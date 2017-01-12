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

#include <cli/model/Recipient.h>

#include <cli/api/api.h>
#include <cli/error/ArgumentError.h>
#include <cli/logger/Logger.h>
#include <cli/loader/PasswordLoader.h>
#include <cli/loader/EmailKeyLoader.h>
#include <cli/loader/CardKeyLoader.h>
#include <cli/loader/PubkeyKeyLoader.h>
#include <cli/loader/PrivkeyKeyLoader.h>
#include <cli/model/KeyRecipient.h>
#include <cli/model/PasswordRecipient.h>

using cli::Crypto;
using cli::model::PasswordRecipient;
using cli::model::KeyRecipient;
using cli::model::Token;
using cli::model::Recipient;
using cli::model::SecureKey;
using cli::loader::PasswordLoader;
using cli::loader::EmailKeyLoader;
using cli::loader::PubkeyKeyLoader;
using cli::loader::PrivkeyKeyLoader;
using cli::loader::CardKeyLoader;


std::string value_or_empty(const std::string& value) {
    return value.empty() ? "empty" : value;
}

// Following line does the trick!
inline MAKE_LOGGABLE(Token, token, out) {
    out << "key: " << value_or_empty(token.key());
    out << ", value: " << value_or_empty(token.value());
    out << ", alias: " << value_or_empty(token.alias());
    return out;
}

std::unique_ptr<Recipient> Recipient::create(const Token& token) {
    DLOG(INFO) << "Create recipient from token";
    auto recipientType = token.key();
    if (recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_PASSWORD) {
        return std::make_unique<PasswordRecipient>(std::make_unique<PasswordLoader>(token.value()));
    } else if (recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_EMAIL) {
        return std::make_unique<KeyRecipient>(std::make_unique<EmailKeyLoader>(token.value()));
    } else if (recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_PUBKEY) {
        return std::make_unique<KeyRecipient>(std::make_unique<PubkeyKeyLoader>(token.value(), token.alias()));
    } else if (recipientType == arg::value::VIRGIL_DECRYPT_KEYPASS_PRIVKEY) {
        return std::make_unique<KeyRecipient>(std::make_unique<PrivkeyKeyLoader>(token.value(), token.alias()));
    } else if (recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_VCARD) {
        return std::make_unique<KeyRecipient>(std::make_unique<CardKeyLoader>(token.value(), token.alias()));
    } else {
        throw error::ArgumentInvalidRecipient(recipientType, arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_VALUES);
    }
}

void Recipient::addSelfTo(
        Crypto::CipherBase& cipher, const virgil::sdk::client::interfaces::ClientInterface& serviceClient) const {
    doAddSelfTo(cipher, serviceClient);
}


void Recipient::decrypt(Crypto::StreamCipher& cipher,
        Crypto::DataSource& source, Crypto::DataSink& sink, const SecureKey& keyPassword,
        const virgil::sdk::client::interfaces::ClientInterface& serviceClient) const {
    doDecrypt(cipher, source, sink, keyPassword, serviceClient);
}
