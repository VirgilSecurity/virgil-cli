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
#include <cli/api/Configurations.h>
#include <cli/command/Command.h>
#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>

#include <cli/model/Token.h>
#include <cli/model/EncryptionRecipient.h>
#include <cli/model/DecryptionRecipient.h>
#include <cli/model/PasswordEncryptionRecipient.h>
#include <cli/model/PasswordDecryptionRecipient.h>
#include <cli/model/KeyEncryptionRecipient.h>
#include <cli/model/KeyDecryptionRecipient.h>

#include <cli/command/KeygenCommand.h>
#include <cli/command/KeyToPubCommand.h>
#include <cli/command/EncryptCommand.h>
#include <cli/command/DecryptCommand.h>

#include <cli/memory.h>

#include <istream>
#include <ostream>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <iterator>

using namespace cli;
using namespace cli::argument;
using namespace cli::command;
using namespace cli::model;

#undef IN
#undef OUT

inline std::string as_optional_string(const Argument& arg) {
    return arg.isString() ? arg.asString() : "";
}

ArgumentIO::ArgumentIO(
        std::unique_ptr<ArgumentSource> argumentSource, std::unique_ptr<ArgumentValueSource> argumentValueSource)
        : argumentSource_(std::move(argumentSource)), argumentValueSource_(std::move(argumentValueSource)) {
    DCHECK(argumentSource_);
    DCHECK(argumentValueSource_);
}

void ArgumentIO::configureUsage(const char* usage, const ArgumentParseOptions& parseOptions) {
    argumentSource_->init(usage, parseOptions);
    argumentValueSource_->init(*argumentSource_);
}

bool ArgumentIO::hasContentInfo() const {
    auto argumentValue = argumentSource_->read(opt::CONTENT_INFO, ArgumentImportance::Optional);
    return !as_optional_string(argumentValue).empty();
}

bool ArgumentIO::hasNoPassword() const {
    return argumentSource_->read(opt::NO_PASSWORD, ArgumentImportance::Optional).asBool();
}

std::unique_ptr<FileDataSource>
ArgumentIO::getInputSource(ArgumentImportance argumentImportance) const {
    ULOG1(INFO)  << tfm::format("Read input.");
    auto argumentValue = argumentSource_->read(opt::IN, argumentImportance);
    return getSource(as_optional_string(argumentValue));
}

std::unique_ptr<FileDataSink>
ArgumentIO::getOutputSink(ArgumentImportance argumentImportance) const {
    ULOG1(INFO)  << tfm::format("Write output.");
    auto argumentValue = argumentSource_->read(opt::OUT, argumentImportance);
    return getSink(as_optional_string(argumentValue));
}


std::unique_ptr<FileDataSource>
ArgumentIO::getContentInfoSource(ArgumentImportance argumentImportance) const {
    ULOG1(INFO)  << tfm::format("Write content info.");
    auto argumentValue = argumentSource_->read(opt::CONTENT_INFO, argumentImportance);
    return getSource(as_optional_string(argumentValue));
}

std::unique_ptr<FileDataSink>
ArgumentIO::getContentInfoSink(ArgumentImportance argumentImportance) const {
    ULOG1(INFO)  << tfm::format("Write content info.");
    auto argumentValue = argumentSource_->read(opt::CONTENT_INFO, argumentImportance);
    return getSink(as_optional_string(argumentValue));
}

std::vector<std::unique_ptr<EncryptionRecipient>>
ArgumentIO::getEncryptionRecipients(ArgumentImportance argumentImportance) const {
    ULOG1(INFO)  << tfm::format("Read recipients for encryption.");
    auto argument = argumentSource_->read(arg::RECIPIENT_ID, argumentImportance);
    std::vector<std::unique_ptr<EncryptionRecipient>> result;
    for (const auto& tokenString : argument.asStringList()) {
        auto recipients = createEncryptionRecipients(tokenString);
        result.insert(result.end(),
                std::make_move_iterator(recipients.begin()), std::make_move_iterator(recipients.end()));
    }
    return result;
}

std::vector<std::unique_ptr<DecryptionRecipient>>
ArgumentIO::getDecryptionRecipients(ArgumentImportance argumentImportance) const {
    ULOG1(INFO)  << tfm::format("Read recipients for decryption.");
    auto argument = argumentSource_->read(arg::KEYPASS, argumentImportance);
    std::vector<std::unique_ptr<DecryptionRecipient>> result;
    for (const auto& tokenString : argument.asStringList()) {
        auto recipients = createDecryptionRecipients(tokenString);
        result.insert(result.end(),
                std::make_move_iterator(recipients.begin()), std::make_move_iterator(recipients.end()));
    }
    return result;
}

std::unique_ptr<KeyAlgorithm> ArgumentIO::getKeyAlgorithm(ArgumentImportance argumentImportance) const {
    auto argumentValue = argumentSource_->read(opt::ALGORITHM, argumentImportance);
    return argumentValueSource_->readKeyAlgorithm(as_optional_string(argumentValue));
}

std::unique_ptr<PrivateKey> ArgumentIO::getPrivateKey(ArgumentImportance argumentImportance) const {
    auto argumentValue = argumentSource_->read(opt::PRIVATE_KEY, argumentImportance);
    return argumentValueSource_->readPrivateKey(as_optional_string(argumentValue));
}

std::unique_ptr<Password> ArgumentIO::getKeyPassword(ArgumentImportance argumentImportance) const {
    auto argumentValue = argumentSource_->read(opt::PRIVATE_KEY_PASSWORD, argumentImportance);
    return argumentValueSource_->readPassword(as_optional_string(argumentValue));
}

std::unique_ptr<Crypto::Text> ArgumentIO::getCommand(ArgumentImportance argumentImportance) const {
    return std::make_unique<Crypto::Text>(argumentSource_->read(arg::COMMAND, argumentImportance).asString());
}

std::unique_ptr<FileDataSource> ArgumentIO::getSource(const std::string& from) const {
    if (from.empty()) {
        ULOG1(INFO)  << tfm::format("Read input from: standard input.");
        return std::make_unique<FileDataSource>();
    } else {
        ULOG1(INFO)  << tfm::format("Read input from file: '%s'.", from);
        return std::make_unique<FileDataSource>(from);
    }
}

std::unique_ptr<FileDataSink> ArgumentIO::getSink(const std::string& from) const {
    if (from.empty()) {
        ULOG1(INFO)  << tfm::format("Write to the standard output.");
        return std::make_unique<FileDataSink>();
    } else {
        ULOG1(INFO)  << tfm::format("Write to the file: '%s'.", from);
        return std::make_unique<FileDataSink>(from);
    }
}

std::vector<std::unique_ptr<EncryptionRecipient>>
ArgumentIO::createEncryptionRecipients(const std::string& tokenString) const {
    Token token(tokenString);
    ULOG1(INFO) << tfm::format("Read recipient(s) from the token: '%s'.", std::to_string(token));

    auto recipientType = token.key();
    std::vector<std::unique_ptr<EncryptionRecipient>> result;
    if (recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_PASSWORD) {
        result.push_back(std::make_unique<PasswordEncryptionRecipient>(
                argumentValueSource_->readPassword(token.value())
        ));
    } else if (recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_PUBKEY) {
        result.push_back(std::make_unique<KeyEncryptionRecipient>(
                argumentValueSource_->readPublicKey(token)
        ));
    } else if (recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_VCARD ||
            recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_EMAIL) {
        auto cards = argumentValueSource_->readCards(token);
        for (const auto& card : *cards) {
            result.push_back(std::make_unique<KeyEncryptionRecipient>(
                    PublicKey(card.publicKeyData(), Crypto::ByteUtils::stringToBytes(card.identifier()))
            ));
        }
    } else {
        throw error::ArgumentInvalidRecipient(recipientType, arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_VALUES);
    }
    return result;
}

std::vector<std::unique_ptr<DecryptionRecipient>>
ArgumentIO::createDecryptionRecipients(const std::string& tokenString) const {
    Token token(tokenString);
    ULOG1(INFO) << tfm::format("Read recipient(s) from the token: '%s'.", std::to_string(token));
    auto recipientType = token.key();
    std::vector<std::unique_ptr<DecryptionRecipient>> result;
    if (recipientType == arg::value::VIRGIL_DECRYPT_KEYPASS_PASSWORD) {
        result.push_back(std::make_unique<PasswordDecryptionRecipient>(
                argumentValueSource_->readPassword(token.value())
        ));
    } else if (recipientType == arg::value::VIRGIL_DECRYPT_KEYPASS_PRIVKEY) {
        auto privateKey = argumentValueSource_->readPrivateKey(token);
        std::unique_ptr<Password> privateKeyPassword;
        if (privateKey->isEncrypted()) {
            bool askPasswordAgain = argumentSource_->read(opt::INTERACTIVE, ArgumentImportance::Optional).asBool();
            auto passwordCorrect = false;
            std::string passwordOption = opt::PRIVATE_KEY_PASSWORD;
            do {
                ULOG1(INFO) << tfm::format("Read password for the private key: '%s'.", std::to_string(token));
                auto argumentValue = argumentSource_->read(passwordOption.c_str(), ArgumentImportance::Required);
                privateKeyPassword =argumentValueSource_->readPassword(as_optional_string(argumentValue));
                passwordCorrect = privateKey->checkPassword(*privateKeyPassword);
                passwordOption = token.value();
            } while (!passwordCorrect && askPasswordAgain);
            if (!passwordCorrect) {
                throw error::ArgumentRuntimeError(
                        tfm::format("Wrong password for the private key '%s'.", std::to_string(token)));
            }
        }
        result.push_back(std::make_unique<KeyDecryptionRecipient>(
                std::move(privateKey), std::move(privateKeyPassword)
        ));
    } else {
        throw error::ArgumentInvalidRecipient(recipientType, arg::value::VIRGIL_DECRYPT_KEYPASS_VALUES);
    }
    return result;
}
