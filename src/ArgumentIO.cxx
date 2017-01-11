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

#include <cli/argument/ArgumentIO.h>

#include <cli/api/api.h>
#include <cli/api/Config.h>
#include <cli/model/Recipient.h>
#include <cli/model/SecureKey.h>
#include <cli/command/Command.h>
#include <cli/error/ArgumentError.h>
#include <cli/logger/Logger.h>

#include <istream>
#include <ostream>
#include <fstream>
#include <iostream>

using cli::Crypto;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentTransformer;
using cli::argument::ArgumentTransformerPtr;
using cli::argument::make_transformer;
using cli::error::ArgumentFileNotFound;
using cli::command::Command;
using cli::model::Recipient;
using cli::model::SecureKey;

bool ArgumentIO::hasContentInfo(const std::unique_ptr<ArgumentSource>& argumentSource) {
    return !argumentSource->readString(opt::CONTENT_INFO, ArgumentImportance::Optional).empty();
}

ArgumentTransformerPtr<Crypto::KeyAlgorithm> ArgumentIO::getKeyAlgorithm(const SourceType& argumentSource) const {
    auto argumentValue = argumentSource->readString(opt::ALGORITHM, ArgumentImportance::Optional);
    return make_transformer<Crypto::KeyAlgorithm>(argumentValue);
}

ArgumentTransformerPtr<Crypto::FileDataSource> ArgumentIO::getInput(const SourceType& argumentSource) const {
    auto argumentValue = argumentSource->readString(opt::IN, ArgumentImportance::Optional);
    return make_transformer<Crypto::FileDataSource>(argumentValue);
}

ArgumentTransformerPtr<Crypto::FileDataSink> ArgumentIO::getOutput(const SourceType& argumentSource) const {
    auto argumentValue = argumentSource->readString(opt::OUT, ArgumentImportance::Optional);
    return make_transformer<Crypto::FileDataSink>(argumentValue);
}

ArgumentTransformerPtr<SecureKey> ArgumentIO::getKeyPassword(const SourceType& argumentSource) const {
    ULOG(1, INFO) << "Read private key password.";
    auto noPassword = argumentSource->readBool(opt::NO_PASSWORD, ArgumentImportance::Optional);
    if (noPassword) {
        return make_transformer<SecureKey>("");
    }
    auto keyPassword = argumentSource->readString(opt::PRIVATE_KEY_PASSWORD, ArgumentImportance::Required);
    return make_transformer<SecureKey>(keyPassword);
}

ArgumentTransformerPtr<SecureKey> ArgumentIO::getKeyPasswordOptional(const SourceType& argumentSource) const {
    ULOG(1, INFO) << "Read optional private key password.";
    auto keyPassword = argumentSource->readString(opt::PRIVATE_KEY_PASSWORD, ArgumentImportance::Optional);
    return make_transformer<SecureKey>(keyPassword);
}

ArgumentTransformerPtr<Command> ArgumentIO::getCommand(const SourceType& argumentSource) const {
    auto argumentValue = argumentSource->readString(arg::COMMAND, ArgumentImportance::Optional);
    return make_transformer<Command>(argumentValue);
}

ArgumentTransformerPtr<Recipient> ArgumentIO::getRecipient(const SourceType& argumentSource) const {
    auto argumentValueList = argumentSource->readStringList(arg::RECIPIENT_ID, ArgumentImportance::Required);
    return make_transformer<Recipient>(argumentValueList);
}

ArgumentTransformerPtr<virgil::sdk::client::Client> ArgumentIO::getClient(const SourceType& argumentSource) const {
    auto applicationToken = argumentSource->readString(opt::APPLICATION_TOKEN, ArgumentImportance::Optional);
    if (applicationToken.empty()) {
        applicationToken = Config::applicationTokenDefault();
    }
    return make_transformer<virgil::sdk::client::Client>(applicationToken);
}

ArgumentTransformerPtr<Crypto::FileDataSource> ArgumentIO::getContentInfoInput(const SourceType& argumentSource) const {
    auto argumentValue = argumentSource->readString(opt::CONTENT_INFO, ArgumentImportance::Required);
    return make_transformer<Crypto::FileDataSource>(argumentValue);
}

ArgumentTransformerPtr<Crypto::FileDataSink> ArgumentIO::getContentInfoOutput(const SourceType& argumentSource) const {
    auto argumentValue = argumentSource->readString(opt::CONTENT_INFO, ArgumentImportance::Required);
    return make_transformer<Crypto::FileDataSink>(argumentValue);
}

ArgumentTransformerPtr<Recipient> ArgumentIO::getDecryptRecipient(
        const SourceType& argumentSource) const {
    auto argumentValueList = argumentSource->readStringList(arg::KEYPASS, ArgumentImportance::Required);
    return make_transformer<Recipient>(argumentValueList);
}
