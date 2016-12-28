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

#ifndef VIRGIL_CLI_ARGUMENTIO_H
#define VIRGIL_CLI_ARGUMENTIO_H

#include <cli/argument/ArgumentRules.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilKeyPair.h>

#include <memory>

namespace cli { namespace argument {

enum class ArgumentImportance {
    Optional,
    Required
};

class ArgumentSource {
public:
    using KeyAlgorithm = virgil::crypto::VirgilKeyPair::Type;
    using Bytes = virgil::crypto::VirgilByteArray;

    class UsageOptions {
    public:
        UsageOptions& enableOptionsFirst();
        UsageOptions& disableOptionsFirst();
        bool isOptionsFirst() const;

        UsageOptions clone() const;

    private:
        bool optionsFirst_ = false;
    };

public:
    void init(const std::string& usage, const UsageOptions& usageOptions);

    std::string readString(const char* argName, ArgumentImportance argImportance) const;

    bool readBool(const char* argName, ArgumentImportance argImportance) const;

    int readInt(const char* argName, ArgumentImportance argImportance) const;

    ArgumentSource* setNextSource(std::unique_ptr<ArgumentSource> source);

    const char *getName() const;

    void setupRules(std::shared_ptr<ArgumentRules> argumentRules);

    std::shared_ptr<const ArgumentRules> argumentRules() const;

private:
    virtual const char* doGetName() const = 0;

    virtual void doInit(const std::string& usage, const UsageOptions& usageOptions) const = 0;

    virtual void doUpdateRules(std::shared_ptr<ArgumentRules> argumentRules) const = 0;

    virtual bool doCanRead(const char* argName, ArgumentImportance argumentImportance) const = 0;

    virtual std::string doReadString(const char* argName) const = 0;

    virtual bool doReadBool(const char* argName) const = 0;

    virtual int doReadInt(const char* argName) const = 0;

private:
    template<typename T>
    class ArgumentReadHelper;

private:
    std::unique_ptr<ArgumentSource> nextSource_;
    std::shared_ptr<ArgumentRules> argumentRules_;
};

}}

namespace std {
    string to_string(cli::argument::ArgumentImportance argumentImportance);
}

#endif //VIRGIL_CLI_ARGUMENTIO_H
