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

#include <cli/argument/ArgumentValue.h>

#include <cli/io/Logger.h>

#include <vector>
#include <cstring>

using cli::argument::ArgumentValue;

static constexpr const char kArgumentValueDelimeters[] = ":=";

static constexpr const char kArgumentValueType_Bool[] = "Boolean";

static std::vector<std::string> split(std::string str, const char* delimiters) {
    std::vector<std::string> result;
    char *token = std::strtok(const_cast<char *>(str.data()), delimiters);
    while (token != nullptr) {
        result.push_back(std::string(token));
        token = std::strtok(nullptr, delimiters);
    }
    return result;
}

ArgumentValue::ArgumentValue() : kind_(ArgumentValue::Kind::Empty) {
    DLOG(INFO) << tfm::format("Created ArgumentValue of type: '%s'.", kindAsString(kind_));
}

ArgumentValue::ArgumentValue(bool value)
        : kind_(ArgumentValue::Kind::Boolean), origin_(std::to_string(value)) {
    value_ = origin_;
    DLOG(INFO) << tfm::format("Created ArgumentValue of type: '%s' from value: '%s'.", kindAsString(kind_), origin_);
}

ArgumentValue::ArgumentValue(size_t value)
        : kind_(ArgumentValue::Kind::Number), origin_(std::to_string(value)) {
    value_ = origin_;
    DLOG(INFO) << tfm::format("Created ArgumentValue of type: '%s' from value: '%s'.", kindAsString(kind_), origin_);
}

ArgumentValue::ArgumentValue(std::string value)
        : kind_(ArgumentValue::Kind::String), origin_(std::move(value)) {
    value_ = origin_;
    DLOG(INFO) << tfm::format("Created ArgumentValue of type: '%s' from value: '%s'.", kindAsString(kind_), origin_);
}

void ArgumentValue::parse() {
    auto tokens = split(origin_, kArgumentValueDelimeters);
    switch (tokens.size()) {
        case 3:
            key_ = tokens[0];
            value_ = tokens[1];
            alias_ = tokens[2];
            kind_ = ArgumentValue::Kind::KeyValueAlias;
            break;
        case 2:
            key_ = tokens[0];
            value_ = tokens[1];
            kind_ = ArgumentValue::Kind::KeyValue;
            break;
        case 1:
            value_ = tokens[0]; // not key_
            kind_ = ArgumentValue::Kind::String;
            break;
        default:
            // Do nothing
            break;
    }
    DLOG(INFO) << tfm::format("Parse ArgumentValue from '%s' to type: '%s'.", origin_, kindAsString(kind_));
}

bool ArgumentValue::isEmpty() const {
    return kind_ == ArgumentValue::Kind::Empty;
}

bool ArgumentValue::isBool() const {
    return kind_ == ArgumentValue::Kind::Boolean;
}

bool ArgumentValue::isNumber() const {
    return kind_ == ArgumentValue::Kind::Number;
}

bool ArgumentValue::isString() const {
    return kind_ == ArgumentValue::Kind::String;
}

bool ArgumentValue::asBool() const {
    throwIfNotKind(ArgumentValue::Kind::Boolean);
    return static_cast<bool>(std::stoul(value_));
}

size_t ArgumentValue::asNumber() const {
    throwIfNotKind(ArgumentValue::Kind::Number);
    return static_cast<size_t>(std::stoul(value_));
}

std::string ArgumentValue::asString() const {
    throwIfNotKind(ArgumentValue::Kind::String);
    return value_;
}

bool ArgumentValue::asOptionalBool() const {
    if (isBool()) {
        return asBool();
    } else if (isNumber()) {
        return asNumber() > 0;
    } else {
        return false;
    }
}

// Complex

bool ArgumentValue::isKeyValue() const {
    return kind_ == ArgumentValue::Kind::KeyValue || kind_ == ArgumentValue::Kind::KeyValueAlias;
}

bool ArgumentValue::isKeyValueAlias() const {
    return kind_ == ArgumentValue::Kind::KeyValueAlias;
}

std::string ArgumentValue::origin() const {
    return origin_;
}

std::string ArgumentValue::key() const {
    return key_;
}

std::string ArgumentValue::value() const {
    return value_;
}

std::string ArgumentValue::alias() const {
    return alias_;
}

std::string ArgumentValue::typeString() const {
    return kindAsString(kind_);
}

std::string std::to_string(const ArgumentValue& argumentValue) {
    if (argumentValue.isKeyValueAlias()) {
        return tfm::format("%s:%s:%s", argumentValue.key(), argumentValue.value(), argumentValue.alias());
    } else if (argumentValue.isKeyValue()) {
        return tfm::format("%s:%s", argumentValue.key(), argumentValue.value());
    } else {
        return argumentValue.value();
    }
}

void ArgumentValue::throwIfNotKind(ArgumentValue::Kind kind) const {
    if (kind_ != kind) {
        throw std::logic_error(tfm::format(
                "Illegal cast ArgumentValue of type '%s' to type '%s'", kindAsString(kind_), kindAsString(kind)));
    }
}

const char* ArgumentValue::kindAsString(ArgumentValue::Kind kind) {
    switch (kind) {
        case ArgumentValue::Kind::Empty:
            return "Empty";
        case ArgumentValue::Kind::Boolean:
            return "Boolean";
        case ArgumentValue::Kind::Number:
            return "Number";
        case ArgumentValue::Kind::String:
            return "String";
        case ArgumentValue::Kind::KeyValue:
            return "KeyValue";
        case ArgumentValue::Kind::KeyValueAlias:
            return "KeyValueAlias";
    }
}
