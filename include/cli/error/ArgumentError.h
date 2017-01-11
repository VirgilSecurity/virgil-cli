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

#ifndef VIRGIL_CLI_ARGUMENT_ERROR_H
#define VIRGIL_CLI_ARGUMENT_ERROR_H

#include <stdexcept>

namespace cli { namespace error {

class ArgumentRuntimeError : public std::runtime_error {
public:
    using runtime_error::runtime_error;
};

class ArgumentLogicError : public std::logic_error {
public:
    using logic_error::logic_error;
};

class ArgumentNotFoundError : public ArgumentRuntimeError {
public:
    explicit ArgumentNotFoundError(const char* argName);
    explicit ArgumentNotFoundError(const std::string& argName);
};

class ArgumentParseError : public ArgumentRuntimeError {
public:
    using ArgumentRuntimeError::ArgumentRuntimeError;
};

class ArgumentTypeError : public ArgumentRuntimeError {
public:
    ArgumentTypeError(const char* argName, const char* expectedType);
    ArgumentTypeError(const std::string& argName, const std::string& expectedType);
};

class ArgumentValueError : public ArgumentRuntimeError {
public:
    ArgumentValueError(const char* argName, const std::string& value);
    ArgumentValueError(const std::string& argName, const std::string& value);
};

class ArgumentNotAllowedError : public ArgumentRuntimeError {
public:
    explicit ArgumentNotAllowedError(const char* argName);
    explicit ArgumentNotAllowedError(const std::string& argName);
};

class ArgumentShowUsageError : public ArgumentRuntimeError {
public:
    ArgumentShowUsageError() : ArgumentRuntimeError("") {}
};

class ArgumentShowVersionError : public ArgumentRuntimeError {
public:
    ArgumentShowVersionError() : ArgumentRuntimeError("") {}
};

class ArgumentFileNotFound : public ArgumentRuntimeError {
public:
    ArgumentFileNotFound(const char* fileName);
    ArgumentFileNotFound(const std::string& fileName);
};

class ArgumentInvalidToken : public ArgumentRuntimeError {
public:
    ArgumentInvalidToken(const char* token);
    ArgumentInvalidToken(const std::string& token);
};

class ArgumentInvalidRecipient : public ArgumentRuntimeError {
public:
    ArgumentInvalidRecipient(const char* recipientKey, const char* validValues[]);
    ArgumentInvalidRecipient(const std::string& recipientKey, const char* validValues[]);
};

class ArgumentRecipientNotFound : public ArgumentRuntimeError {
public:
    ArgumentRecipientNotFound(const std::string& sourceType, const std::string& sourceValue);
};

}}

#endif //VIRGIL_CLI_ARGUMENT_ERROR_H
