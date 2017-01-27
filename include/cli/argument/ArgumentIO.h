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

#include <cli/argument/Argument.h>
#include <cli/argument/ArgumentImportance.h>
#include <cli/argument/ArgumentSource.h>
#include <cli/argument/ArgumentValueSource.h>

#include <cli/model/Password.h>
#include <cli/model/KeyAlgorithm.h>
#include <cli/model/EncryptCredentials.h>
#include <cli/model/DecryptCredentials.h>
#include <cli/model/ServiceConfig.h>
#include <cli/model/PrivateKey.h>
#include <cli/model/SignerCredentials.h>
#include <cli/model/CardIdentity.h>
#include <cli/model/CardData.h>
#include <cli/model/CardInfo.h>
#include <cli/model/SecureValue.h>
#include <cli/model/ApplicationCredentials.h>

#include <memory>
#include <string>

namespace cli { namespace argument {

class ArgumentIO {
public:
    ArgumentIO(
            std::unique_ptr<ArgumentSource> argumentSource, std::unique_ptr<ArgumentValueSource> argumentValueSource);

    void configureUsage(const char* usage, const ArgumentParseOptions& parseOptions);

    // Check
    bool hasContentInfo() const;

    bool hasNoPassword() const;

    bool isInteractive() const;

    // Get
    std::vector<std::unique_ptr<model::EncryptCredentials>>
    getEncryptCredentials(ArgumentImportance argumentImportance) const;

    std::vector<std::unique_ptr<model::DecryptCredentials>>
    getDecryptCredentials(ArgumentImportance argumentImportance) const;

    model::SecureValue getInput(ArgumentImportance argumentImportance) const;

    model::FileDataSource getInputSource(ArgumentImportance argumentImportance) const;

    model::FileDataSink getOutputSink(ArgumentImportance argumentImportance) const;

    model::FileDataSource getContentInfoSource(ArgumentImportance argumentImportance) const;

    model::FileDataSink getContentInfoSink(ArgumentImportance argumentImportance) const;

    model::KeyAlgorithm getKeyAlgorithm(ArgumentImportance argumentImportance) const;

    model::Password getKeyPassword(ArgumentImportance argumentImportance) const;

    model::PrivateKey getPrivateKey(ArgumentImportance argumentImportance) const;

    model::PublicKey getSenderKey(ArgumentImportance argumentImportance) const;

    model::FileDataSource getSignatureSource(ArgumentImportance argumentImportance) const;

    Crypto::Text getCommand(ArgumentImportance argumentImportance) const;

    model::CardIdentity getCardIdentity(ArgumentImportance argumentImportance) const;

    Crypto::Text getCardScope(ArgumentImportance argumentImportance) const;

    model::CardData getCardData(ArgumentImportance argumentImportance) const;

    model::CardInfo getCardInfo(ArgumentImportance argumentImportance) const;

    model::SecureValue getAppAccessToken(ArgumentImportance argumentImportance) const;

    model::ApplicationCredentials getAppCredentials(ArgumentImportance argumentImportance) const;

private:
    model::FileDataSource getSource(const ArgumentValue& argumentValue) const;

    model::FileDataSink getSink(const ArgumentValue& argumentValue) const;

    void readPrivateKeyPassword(model::PrivateKey& privateKey, const ArgumentValue& argumentValue) const;

    std::vector<std::unique_ptr<model::EncryptCredentials>>
    readEncryptCredentials(const ArgumentValue& argumentValue) const;

    std::vector<std::unique_ptr<model::DecryptCredentials>>
    readDecryptCredentials(const ArgumentValue& argumentValue) const;

    model::PublicKey readSenderKey(const ArgumentValue& argumentValue) const;

private:
    std::unique_ptr<ArgumentSource> argumentSource_;
    std::unique_ptr<ArgumentValueSource> argumentValueSource_;
};

}}

#endif //VIRGIL_CLI_ARGUMENT_IO_H
