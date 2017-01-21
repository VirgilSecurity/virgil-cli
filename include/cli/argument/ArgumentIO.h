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
#include <cli/model/EncryptionRecipient.h>
#include <cli/model/DecryptionRecipient.h>
#include <cli/model/ServiceConfig.h>

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

    // Get
    std::vector<std::unique_ptr<model::EncryptionRecipient>>
    getEncryptionRecipients(ArgumentImportance argumentImportance) const;

    std::vector<std::unique_ptr<model::DecryptionRecipient>>
    getDecryptionRecipients(ArgumentImportance argumentImportance) const;

    std::unique_ptr<model::FileDataSource> getInputSource(ArgumentImportance argumentImportance) const;

    std::unique_ptr<model::FileDataSink> getOutputSink(ArgumentImportance argumentImportance) const;

    std::unique_ptr<model::FileDataSource> getContentInfoSource(ArgumentImportance argumentImportance) const;

    std::unique_ptr<model::FileDataSink> getContentInfoSink(ArgumentImportance argumentImportance) const;

    std::unique_ptr<model::KeyAlgorithm> getKeyAlgorithm(ArgumentImportance argumentImportance) const;

    std::unique_ptr<model::Password> getKeyPassword(ArgumentImportance argumentImportance) const;

    std::unique_ptr<Crypto::Text> getCommand(ArgumentImportance argumentImportance) const;

private:
    std::vector<std::unique_ptr<model::EncryptionRecipient>>
    createEncryptionRecipients(const std::string& tokenString) const;

    std::vector<std::unique_ptr<model::DecryptionRecipient>>
    createDecryptionRecipients(const std::string& tokenString) const;

    std::unique_ptr<model::FileDataSource> getSource(const std::string& from) const;

    std::unique_ptr<model::FileDataSink> getSink(const std::string& from) const;

private:
    std::unique_ptr<ArgumentSource> argumentSource_;
    std::unique_ptr<ArgumentValueSource> argumentValueSource_;
};

}}

#endif //VIRGIL_CLI_ARGUMENT_IO_H
