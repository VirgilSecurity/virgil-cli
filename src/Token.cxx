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

#include <cli/model/Token.h>

#include <cli/api/api.h>
#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>

#include <sstream>
#include <vector>

using cli::model::Token;
using cli::error::ArgumentInvalidToken;

static constexpr const char kTokenDelim = ':';

static std::vector<std::string> split(const std::string& str, char delim) {
    std::stringstream ss;
    ss.str(str);
    std::string item;
    std::vector<std::string> result;
    while (std::getline(ss, item, delim)) {
        result.push_back(item);
    }
    return result;
}

Token::Token(const std::string& tokenString) {
    LOG(INFO) << tfm::format("Create token from the string '%s'.", tokenString);
    auto tokens = split(tokenString, kTokenDelim);
    switch (tokens.size()) {
        case 3:
            alias_ = tokens[2];
            // no break
        case 2:
            value_ = tokens[1];
            // no break
        case 1:
            key_ = tokens[0];
            // no break
        default:
            // do nothing, validation will be later
            break;
    }

    LOG(INFO) << "Start token validation.";
    if (key_.empty()) {
        LOG(ERROR) << "Token validation failed: token's key is not defined.";
        throw ArgumentInvalidToken(tokenString);
    }

    if (value_.empty()) {
        LOG(ERROR) << "Token validation failed: token's value is not defined.";
        throw ArgumentInvalidToken(tokenString);
    }
}

std::string Token::key() const {
    return key_;
}

std::string Token::value() const {
    return value_;
}

std::string Token::alias() const {
    return alias_;
}

std::string std::to_string(const Token& token) {
    std::ostringstream ss;
    ss << token.key() << kTokenDelim;
    if (token.key() == cli::arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_PASSWORD ||
            token.key() == cli::arg::value::VIRGIL_DECRYPT_KEYPASS_PRIVKEY) {
#if defined(NDEBUG) || defined(_NDEBUG)
        ss << "<hidden>";
#else
        ss << token.value();
#endif
    } else {
        ss << token.value();
    }
    if (!token.alias().empty()) {
        ss << kTokenDelim << token.alias();
    }
    return ss.str();
}
