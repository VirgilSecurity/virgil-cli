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

#ifndef VIRGIL_CLI_ARGUMENT_VALIDATION_HUB_H
#define VIRGIL_CLI_ARGUMENT_VALIDATION_HUB_H

#include <cli/argument/validation/ArgumentAnyValidation.h>
#include <cli/argument/validation/ArgumentNotEmptyValidation.h>
#include <cli/argument/validation/ArgumentTextValidation.h>
#include <cli/argument/validation/ArgumentBoolValidation.h>
#include <cli/argument/validation/ArgumentEnumValidation.h>
#include <cli/argument/validation/ArgumentRangeValidation.h>
#include <cli/argument/validation/ArgumentKeyValueValidation.h>
#include <cli/argument/validation/ArgumentKeyValueAliasValidation.h>

namespace cli { namespace argument { namespace validation {

class ArgumentValidationHub {
public:
    static std::unique_ptr<ArgumentAnyValidation> isAny();

    static std::unique_ptr<ArgumentNotEmptyValidation> isNotEmpty();

    static std::unique_ptr<ArgumentTextValidation> isText();

    static std::unique_ptr<ArgumentBoolValidation> isBool();

    static std::unique_ptr<ArgumentEnumValidation> isEnum(const char** validValues);

    static std::unique_ptr<ArgumentRangeValidation> isRange(size_t min, size_t max);

    static std::unique_ptr<ArgumentKeyValueValidation> isKeyValue();

    static std::unique_ptr<ArgumentKeyValueAliasValidation> isKeyValueAlias();

    ArgumentValidationHub() = delete;
};

}}}

#endif //VIRGIL_CLI_ARGUMENT_VALIDATION_HUB_H
