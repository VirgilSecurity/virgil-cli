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

#ifndef VIRGIL_CLI_ARGUMENT_VALUE_SOURCE_H
#define VIRGIL_CLI_ARGUMENT_VALUE_SOURCE_H

#include <cli/argument/ArgumentSource.h>

#include <cli/model/Card.h>
#include <cli/model/PublicKey.h>
#include <cli/model/PrivateKey.h>
#include <cli/model/Password.h>
#include <cli/model/KeyAlgorithm.h>
#include <cli/model/ServiceConfig.h>
#include <cli/model/EncryptCredentials.h>
#include <cli/model/DecryptCredentials.h>

#include <memory>
#include <string>
#include <vector>

namespace cli { namespace argument {

class ArgumentValueSource {
public:
    const char* getName() const;

    void init(const ArgumentSource& argumentSource);

    ArgumentValueSource* appendSource(std::shared_ptr<ArgumentValueSource> source);

    model::KeyAlgorithm readKeyAlgorithm(const ArgumentValue& argumentValue) const;

    model::Password readPassword(const ArgumentValue& argumentValue) const;

    model::PublicKey readPublicKey(const ArgumentValue& argumentValue) const;

    model::PrivateKey readPrivateKey(const ArgumentValue& argumentValue) const;

    std::vector<model::Card> readCards(const ArgumentValue& argumentValue) const;

private:
    virtual void doInit(const ArgumentSource& argumentSource) = 0;

    virtual const char* doGetName() const = 0;

    virtual std::unique_ptr<model::KeyAlgorithm> doReadKeyAlgorithm(const ArgumentValue& argumentValue) const;

    virtual std::unique_ptr<model::Password> doReadPassword(const ArgumentValue& argumentValue) const;

    virtual std::unique_ptr<model::PublicKey> doReadPublicKey(const ArgumentValue& argumentValue) const;

    virtual std::unique_ptr<model::PrivateKey> doReadPrivateKey(const ArgumentValue& argumentValue) const;

    virtual std::unique_ptr<std::vector<model::Card>> doReadCards(const ArgumentValue& argumentValue) const;

private:
    std::shared_ptr<ArgumentValueSource> nextSource_;
};

}}

#endif //VIRGIL_CLI_ARGUMENT_VALUE_SOURCE_H
