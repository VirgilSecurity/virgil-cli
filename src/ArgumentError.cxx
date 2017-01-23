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

#include <cli/error/ArgumentError.h>

#include <tinyformat/tinyformat.h>

using namespace cli::error;

static constexpr const char* kNotFoundErrorMessage =
        "Argument '%s' is not defined.";

static constexpr const char* kNotAllowedErrorMessage =
        "Argument %s is not allowed for this command.";

static constexpr const char* kTypeErrorMessage =
        "Argument %s is not of type: %s.";

static constexpr const char* kValueErrorMessage =
        "Argument '%s' has unexpected value: '%s'.";

static constexpr const char* kFileNotFoundMessage =
        "File '%s' is not found.";

static constexpr const char* kInvalidTokenMessage =
        "Invalid token format '%s', expected '<key>:<value>[:<alias>]'.";

static constexpr const char* kInvalidRecipientMessage =
        "Invalid recipient key '%s', expected on of '%s'.";

static constexpr const char* kRecipientNotFoundMessage =
        "Recipient not found '%s:%s'.";

static constexpr const char* kRecipientDecryptionErrorMessage =
        "Data can not be decrypted with given password or private key.";

static constexpr const char* kValueSourceErrorMessage =
        "Argument value '%s' can not be recognized.";

static constexpr const char* kInvalidKeyValueMessage =
        "Invalid key-value format '%s', expected '<key>=<value>'.";

static std::string format_api_list(const char *list[]) {
    std::string result = "{";
    for (auto item = list; *item != nullptr; ++item) {
        if (item != list) {
            result += ", ";
        }
        result += *item;
    }
    result += "}";
    return result;
}

ArgumentNotFoundError::ArgumentNotFoundError(const char* argName) :
        ArgumentRuntimeError(tfm::format(kNotFoundErrorMessage, argName)) {}

ArgumentNotFoundError::ArgumentNotFoundError(const std::string& argName) :
        ArgumentRuntimeError(tfm::format(kNotFoundErrorMessage, argName)) {}

ArgumentNotAllowedError::ArgumentNotAllowedError(const char* argName) :
        ArgumentRuntimeError(tfm::format(kNotAllowedErrorMessage, argName)) {}

ArgumentNotAllowedError::ArgumentNotAllowedError(const std::string& argName) :
        ArgumentRuntimeError(tfm::format(kNotAllowedErrorMessage, argName)) {}

ArgumentTypeError::ArgumentTypeError(const char* argName, const char* expectedType) :
        ArgumentRuntimeError(tfm::format(kTypeErrorMessage, argName, expectedType)) {}

ArgumentTypeError::ArgumentTypeError(const std::string& argName, const std::string& expectedType) :
        ArgumentRuntimeError(tfm::format(kTypeErrorMessage, argName, expectedType)) {}

ArgumentValueError::ArgumentValueError(const char* argName, const std::string& value) :
        ArgumentRuntimeError(tfm::format(kValueErrorMessage, argName, value)) {}

ArgumentValueError::ArgumentValueError(const std::string& argName, const std::string& value) :
        ArgumentRuntimeError(tfm::format(kValueErrorMessage, argName, value)) {}

ArgumentFileNotFound::ArgumentFileNotFound(const char* fileName) :
        ArgumentRuntimeError(tfm::format(kFileNotFoundMessage, fileName)) {}

ArgumentFileNotFound::ArgumentFileNotFound(const std::string& fileName) :
        ArgumentRuntimeError(tfm::format(kFileNotFoundMessage, fileName)) {}

ArgumentInvalidToken::ArgumentInvalidToken(const char* token) :
        ArgumentRuntimeError(tfm::format(kInvalidTokenMessage, token)) {}

ArgumentInvalidToken::ArgumentInvalidToken(const std::string& token) :
        ArgumentRuntimeError(tfm::format(kInvalidTokenMessage, token)) {}

ArgumentInvalidRecipient::ArgumentInvalidRecipient(const char* recipientKey, const char* validValues[]) :
        ArgumentRuntimeError(tfm::format(kInvalidRecipientMessage, recipientKey, format_api_list(validValues))) {}

ArgumentInvalidRecipient::ArgumentInvalidRecipient(const std::string& recipientKey, const char* validValues[]) :
        ArgumentRuntimeError(tfm::format(kInvalidRecipientMessage, recipientKey, format_api_list(validValues))) {}

ArgumentRecipientNotFound::ArgumentRecipientNotFound(const std::string& sourceType, const std::string& sourceValue) :
        ArgumentRuntimeError(tfm::format(kRecipientNotFoundMessage, sourceType, sourceValue)) {}

ArgumentRecipientDecryptionError::ArgumentRecipientDecryptionError() :
        ArgumentRuntimeError(tfm::format(kRecipientDecryptionErrorMessage)) {}

ArgumentValueSourceError::ArgumentValueSourceError(const std::string& value) :
        ArgumentRuntimeError(tfm::format(kValueSourceErrorMessage, value)) {}


ArgumentInvalidKeyValue::ArgumentInvalidKeyValue(const char* token) :
        ArgumentRuntimeError(tfm::format(kInvalidTokenMessage, token)) {}

ArgumentInvalidKeyValue::ArgumentInvalidKeyValue(const std::string& token) :
        ArgumentRuntimeError(tfm::format(kInvalidKeyValueMessage, token)) {}
