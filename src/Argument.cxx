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

#include <cli/argument/Argument.h>

#include <cli/memory.h>
#include <cli/io/Logger.h>

using cli::argument::Argument;
using cli::argument::ArgumentValue;

Argument::Argument() : values_() {}

Argument::Argument(bool value) : values_({ ArgumentValue(value) }) {}

Argument::Argument(size_t value) : values_({ ArgumentValue(value) }) {}

Argument::Argument(std::string value) : values_({ ArgumentValue(std::move(value)) }) {
}

Argument::Argument(std::vector<std::string> valueList) : values_() {
    for (auto&& value : valueList) {
        values_.push_back(ArgumentValue(std::move(value)));
    }
}

void Argument::parse() {
    for (auto& argumentValue : values_) {
        argumentValue.parse();
    }
}

bool Argument::isEmpty() const {
    return values_.empty();
}

bool Argument::isValue() const {
    return values_.size() == 1;
}

bool Argument::isList() const {
    return values_.size() > 0;
}

ArgumentValue Argument::asValue() const {
    if (isEmpty()) {
        return ArgumentValue();
    } else {
        return values_[0];
    }
}

std::vector<ArgumentValue> Argument::asList() const {
    return values_;
}
