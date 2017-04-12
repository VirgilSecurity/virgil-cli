/**
 * Copyright (C) 2015-2017 Virgil Security Inc.
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

#ifndef VIRGIL_CLI_ARGUMENT_SOURCE_H
#define VIRGIL_CLI_ARGUMENT_SOURCE_H

#include <cli/argument/Argument.h>
#include <cli/argument/ArgumentRules.h>
#include <cli/argument/ArgumentImportance.h>
#include <cli/argument/ArgumentParseOptions.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilKeyPair.h>

#include <memory>
#include <vector>

namespace cli { namespace argument {

class ArgumentSource {
public:
    void init(const std::string& usage, const ArgumentParseOptions& parseOptions);

    const char *getName() const;

    Argument read(const char* argName, ArgumentImportance argImportance) const;

    Argument readSecure(const char* argName, ArgumentImportance argImportance) const;

    Argument read(const std::vector<const char *>& argNames, ArgumentImportance argImportance) const;

    ArgumentSource* appendSource(std::unique_ptr<ArgumentSource> source);

    ArgumentSource* insertSource(std::unique_ptr<ArgumentSource> source);

    void setupRules(std::shared_ptr<ArgumentRules> argumentRules);

    std::shared_ptr<ArgumentRules> getArgumentRules();

    std::shared_ptr<const ArgumentRules> getArgumentRules() const;

private:
    virtual const char* doGetName() const = 0;

    virtual void doInit(const std::string& usage, const ArgumentParseOptions& usageOptions) = 0;

    virtual void doUpdateRules() = 0;

    virtual bool doCanRead(const char* argName, ArgumentImportance argumentImportance) const = 0;

    virtual Argument doRead(const char* argName) const = 0;

    virtual Argument doReadSecure(const char* argName) const;

private:
    Argument internalRead(const char* argName, ArgumentImportance argImportance, bool isSecure) const;

private:
    std::unique_ptr<ArgumentSource> nextSource_;
    std::shared_ptr<ArgumentRules> argumentRules_;
};

}}

#endif //VIRGIL_CLI_ARGUMENT_SOURCE_H
