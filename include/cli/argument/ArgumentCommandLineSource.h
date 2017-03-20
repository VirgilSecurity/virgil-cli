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

#ifndef VIRGIL_CLI_ARGUMENT_COMMAND_LINE_SOURCE_H
#define VIRGIL_CLI_ARGUMENT_COMMAND_LINE_SOURCE_H

#include <cli/argument/ArgumentSource.h>

#include <memory>
#include <string>
#include <vector>

namespace cli { namespace argument {

class ArgumentCommandLineSource : public ArgumentSource {
public:
    ArgumentCommandLineSource(const std::vector<std::string>& args);
    ArgumentCommandLineSource(const char* argvStart[], const char* argvEnd[]);
public:
    virtual const char* doGetName() const override;
    virtual void doInit(const std::string& usage, const ArgumentParseOptions& usageOptions) override;
    virtual void doUpdateRules() override;
    virtual bool doCanRead(const char* argName, ArgumentImportance argumentImportance) const override;
    virtual Argument doRead(const char* argName) const override;
public:
    ArgumentCommandLineSource(ArgumentCommandLineSource&&);
    ArgumentCommandLineSource& operator=(ArgumentCommandLineSource&&);
    virtual ~ArgumentCommandLineSource() noexcept;
private:
    void parseArguments(const std::string& usage, const ArgumentParseOptions& usageOptions);
    void processArguments();
    void processConfigOverloads();
    void processConfigSources();
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}}

#endif //VIRGIL_CLI_ARGUMENT_COMMAND_LINE_SOURCE_H
