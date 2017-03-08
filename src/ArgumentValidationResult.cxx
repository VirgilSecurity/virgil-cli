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

#include <cli/argument/validation/ArgumentValidationResult.h>

#include <cli/error/ArgumentError.h>

using cli::argument::validation::ArgumentValidationResult;
using cli::error::ArgumentValidationError;

ArgumentValidationResult ArgumentValidationResult::success() {
    return ArgumentValidationResult(true, "");
}

ArgumentValidationResult ArgumentValidationResult::failure(const std::string& message) {
    return ArgumentValidationResult(false, message);
}

ArgumentValidationResult::ArgumentValidationResult(bool result, const std::string& message)
        : result_(result), message_(message) {
}

ArgumentValidationResult::operator bool() const noexcept {
    return result_;
}

std::string ArgumentValidationResult::errorMessage() const {
    return message_;
}

ArgumentValidationResult ArgumentValidationResult::append(const std::string& message) const {
    if (!result_) {
        return ArgumentValidationResult::failure(message_ + message);
    }
    return *this;
}

ArgumentValidationResult ArgumentValidationResult::prepend(const std::string& message) const {
    if (!result_) {
        return ArgumentValidationResult::failure(message + message_);
    }
    return *this;
}

void ArgumentValidationResult::check() const {
    if (!result_) {
        throw ArgumentValidationError(message_);
    }
}

ArgumentValidationResult& ArgumentValidationResult::operator+=(const ArgumentValidationResult& other) {
    *this = *this + other;
    return *this;
}

ArgumentValidationResult operator+(const ArgumentValidationResult& lhs, const ArgumentValidationResult& rhs) {
    if (lhs && rhs) {
        return ArgumentValidationResult::success();
    } else if (!lhs && !rhs) {
        return ArgumentValidationResult::failure(lhs.errorMessage() + " " + rhs.errorMessage());
    } else {
        return !lhs ? lhs : rhs;
    }
}
