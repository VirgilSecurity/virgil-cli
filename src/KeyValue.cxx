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

#include <cli/model/KeyValue.h>

#include <cli/api/api.h>
#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>

#include <sstream>
#include <vector>

using cli::model::KeyValue;
using cli::error::ArgumentInvalidKeyValue;

static constexpr const char kKeyValueDelim = '=';

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

KeyValue::KeyValue(const std::string& tokenString) {
    LOG(INFO) << tfm::format("Create token from the string '%s'.", tokenString);
    auto tokens = split(tokenString, kKeyValueDelim);
    switch (tokens.size()) {
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
        LOG(ERROR) << "KeyValue validation failed: key is not defined.";
        throw ArgumentInvalidKeyValue(tokenString);
    }

    if (value_.empty()) {
        LOG(ERROR) << "KeyValue validation failed: value is not defined.";
        throw ArgumentInvalidKeyValue(tokenString);
    }
}

std::string KeyValue::key() const {
    return key_;
}

std::string KeyValue::value() const {
    return value_;
}

std::string std::to_string(const KeyValue& token) {
    std::ostringstream ss;
    ss << token.key() << kKeyValueDelim;
#if defined(NDEBUG) || defined(_NDEBUG)
    ss << "<hidden>";
#else
    ss << token.value();
#endif
    return ss.str();
}
