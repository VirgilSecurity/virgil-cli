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

#include <cli/argument/validation/ArgumentValidation.h>

#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>

using cli::argument::Argument;
using cli::argument::ArgumentValue;
using cli::argument::ArgumentImportance;
using cli::argument::validation::ArgumentValidation;
using cli::argument::validation::ArgumentValidationResult;
using cli::error::ArgumentValidationError;

void ArgumentValidation::validate(const Argument& argument, ArgumentImportance argumentImportance) const {
    tryValidate(argument, argumentImportance).check();
}

void ArgumentValidation::validateList(const Argument& argument, ArgumentImportance argumentImportance) const {
    tryValidateList(argument, argumentImportance).check();
}

void ArgumentValidation::validate(const ArgumentValue& argumentValue) const {
    tryValidate(argumentValue).check();
}

ArgumentValidationResult ArgumentValidation::tryValidate(
        const Argument& argument, ArgumentImportance argumentImportance) const {
    auto argumentValue = argument.asValue();
    if (argumentImportance == ArgumentImportance::Optional && (argument.isEmpty() || argumentValue.isEmpty())) {
        return ArgumentValidationResult::success();
    }
    if (argument.isEmpty()) {
        return ArgumentValidationResult::failure("Expected one argument, but got empty.");
    } else if (!argument.isValue()) {
        return ArgumentValidationResult::failure("Expected one argument, but got more then one.");
    }
    return tryValidate(argumentValue);
}

ArgumentValidationResult ArgumentValidation::tryValidateList(
        const Argument& argument, ArgumentImportance argumentImportance) const {

    if (argumentImportance == ArgumentImportance::Optional && argument.isEmpty()) {
        return ArgumentValidationResult::success();
    }
    if (argument.isEmpty()) {
        return ArgumentValidationResult::failure("Expected one or more arguments, but got zero.");
    }
    ArgumentValidationResult validationResult = ArgumentValidationResult::success();
    for (const auto argumentValue : argument.asList()) {
        if (!argumentValue.isEmpty()) {
            validationResult += tryValidate(argumentValue);
        } else {
            auto errorMessage = "Met empty value in the arguments list.";
            if (argumentImportance != ArgumentImportance::Optional) {
                ULOG(WARNING) << errorMessage;
            } else {
                return ArgumentValidationResult::failure(errorMessage);
            }
        }
    }
    return validationResult;
}

ArgumentValidationResult ArgumentValidation::tryValidate(const ArgumentValue& argumentValue) const {
    return doValidate(argumentValue);
}
