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

#include <cli/argument/validation/ArgumentKeyValueValidation.h>

#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>

using cli::argument::ArgumentValue;
using cli::argument::ArgumentImportance;
using cli::argument::validation::ArgumentKeyValueValidation;
using cli::argument::validation::ArgumentValidationResult;
using cli::error::ArgumentValidationError;

ArgumentValidationResult ArgumentKeyValueValidation::doValidate(const ArgumentValue& argumentValue) const {
    if (!argumentValue.isKeyValue()) {
        return ArgumentValidationResult::failure(
                tfm::format("Expected KeyValue, but found value of the type %s.", argumentValue.typeString()));
    }
    return validateKey(argumentValue) + validateValue(argumentValue);
}

void ArgumentKeyValueValidation::setKeyValidation(std::unique_ptr<ArgumentValidation> keyValidation) {
    keyValidation_ = std::move(keyValidation);
}

void ArgumentKeyValueValidation::setValueValidation(
        std::unique_ptr<ArgumentValidation> valueValidation, std::string key) {
    valueValidation_[key] = std::move(valueValidation);
}

ArgumentValidationResult ArgumentKeyValueValidation::validateKey(const ArgumentValue& argumentValue) const {
    if (keyValidation_) {
        return keyValidation_->tryValidate(ArgumentValue(argumentValue.key()))
                .prepend("Key validation: ");
    }
    return ArgumentValidationResult::success();
}

ArgumentValidationResult ArgumentKeyValueValidation::validateValue(const ArgumentValue& argumentValue) const {
    auto foundValidation = valueValidation_.find(argumentValue.key());
    if (foundValidation != valueValidation_.cend()) {
        return foundValidation->second->tryValidate(ArgumentValue(argumentValue.value()))
                .prepend("Value validation: ");
    }
    return ArgumentValidationResult::success();
}
