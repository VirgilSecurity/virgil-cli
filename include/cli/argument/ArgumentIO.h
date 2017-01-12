/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in argumentSource and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of argumentSource code must retain the above copyright
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

#ifndef VIRGIL_CLI_ARGUMENT_IO_H
#define VIRGIL_CLI_ARGUMENT_IO_H

#include <cli/crypto/Crypto.h>

#include <cli/argument/ArgumentSource.h>
#include <cli/argument/ArgumentTransformer.h>

#include <virgil/sdk/client/Client.h>

#include <memory>
#include <string>

namespace cli { namespace argument {

class ArgumentIO {
public:
    using SourceType = std::shared_ptr<ArgumentSource>;
public:
    // Check
    bool hasContentInfo(const SourceType& argumentSource);

    // Readers
    ArgumentTransformerPtr<Crypto::KeyAlgorithm> getKeyAlgorithm(const SourceType& argumentSource) const;

    ArgumentTransformerPtr<Crypto::FileDataSource> getInput(const SourceType& argumentSource) const;

    ArgumentTransformerPtr<Crypto::FileDataSink> getOutput(const SourceType& argumentSource) const;

    ArgumentTransformerPtr<model::SecureKey> getKeyPassword(const SourceType& argumentSource) const;

    ArgumentTransformerPtr<model::SecureKey> getKeyPasswordOptional(const SourceType& argumentSource) const;

    ArgumentTransformerPtr<command::Command> getCommand(const SourceType& argumentSource) const;

    ArgumentTransformerPtr<model::Recipient> getRecipient(const SourceType& argumentSource) const;

    ArgumentTransformerPtr<virgil::sdk::client::Client> getClient(const SourceType& argumentSource) const;

    ArgumentTransformerPtr<Crypto::FileDataSource> getContentInfoInput(const SourceType& argumentSource) const;

    ArgumentTransformerPtr<Crypto::FileDataSink> getContentInfoOutput(const SourceType& argumentSource) const;

    ArgumentTransformerPtr<model::Recipient> getDecryptRecipient(const SourceType& argumentSource) const;

};

}}

#endif //VIRGIL_CLI_ARGUMENT_IO_H
