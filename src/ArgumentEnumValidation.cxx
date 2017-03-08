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

#include <cli/argument/validation/ArgumentEnumValidation.h>

#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>

#include <cstring>

using cli::argument::ArgumentValue;
using cli::argument::validation::ArgumentEnumValidation;
using cli::argument::validation::ArgumentValidationResult;
using cli::error::ArgumentLogicError;
using cli::error::ArgumentValidationError;

ArgumentEnumValidation::ArgumentEnumValidation(const char** validValues) : validValues_(validValues) {
    if (validValues_ == nullptr) {
        throw ArgumentLogicError("ArgumentEnumValidation: valid values are not defined.");
    }
}

ArgumentValidationResult ArgumentEnumValidation::doValidate(const ArgumentValue& argumentValue) const {
    if (!argumentValue.isString()) {
        return ArgumentValidationResult::failure(
                tfm::format("Expected enum string, but found value of the type %s.", argumentValue.typeString()));
    }
    return check(argumentValue.asString().c_str());
}

std::string ArgumentEnumValidation::formatValidValues() const {
    std::string result = "{";
    for (auto item = validValues_; *item != nullptr; ++item) {
        if (item != validValues_) {
            result += ", ";
        }
        result += *item;
    }
    result += "}";
    return result;
}

ArgumentValidationResult ArgumentEnumValidation::check(const char* value) const {
    for (auto item = validValues_; *item != nullptr; ++item) {
        if (strcmp(*item, value) == 0) {
            return ArgumentValidationResult::success();
        }
    }
    return ArgumentValidationResult::failure(
            tfm::format("Expected one of the values %s, but got '%s'.", formatValidValues(), value));
}
