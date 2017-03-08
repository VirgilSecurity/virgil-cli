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

#include <cli/argument/validation/ArgumentValidationHub.h>

#include <cli/memory.h>

using cli::argument::validation::ArgumentValidationHub;
using cli::argument::validation::ArgumentAnyValidation;
using cli::argument::validation::ArgumentNotEmptyValidation;
using cli::argument::validation::ArgumentTextValidation;
using cli::argument::validation::ArgumentBoolValidation;
using cli::argument::validation::ArgumentNumberValidation;
using cli::argument::validation::ArgumentEnumValidation;
using cli::argument::validation::ArgumentRangeValidation;
using cli::argument::validation::ArgumentKeyValueValidation;
using cli::argument::validation::ArgumentKeyValueAliasValidation;

std::unique_ptr<ArgumentAnyValidation> ArgumentValidationHub::isAny() {
    return std::make_unique<ArgumentAnyValidation>();
}

std::unique_ptr<ArgumentNotEmptyValidation> ArgumentValidationHub::isNotEmpty() {
    return std::make_unique<ArgumentNotEmptyValidation>();
}

std::unique_ptr<ArgumentTextValidation> ArgumentValidationHub::isText() {
    return std::make_unique<ArgumentTextValidation>();
}

std::unique_ptr<ArgumentBoolValidation> ArgumentValidationHub::isBool() {
    return std::make_unique<ArgumentBoolValidation>();
}

std::unique_ptr<ArgumentNumberValidation> ArgumentValidationHub::isNumber() {
    return std::make_unique<ArgumentNumberValidation>();
}

std::unique_ptr<ArgumentEnumValidation> ArgumentValidationHub::isEnum(const char** validValues) {
    return std::make_unique<ArgumentEnumValidation>(validValues);
}

std::unique_ptr<ArgumentRangeValidation> ArgumentValidationHub::isRange(size_t min, size_t max) {
    return std::make_unique<ArgumentRangeValidation>(min, max);
}

std::unique_ptr<ArgumentKeyValueValidation> ArgumentValidationHub::isKeyValue() {
    return std::make_unique<ArgumentKeyValueValidation>();
}

std::unique_ptr<ArgumentKeyValueAliasValidation> ArgumentValidationHub::isKeyValueAlias() {
    return std::make_unique<ArgumentKeyValueAliasValidation>();
}
