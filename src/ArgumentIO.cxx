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

#include <cli/model/EncryptCredentials.h>
#include <cli/model/DecryptCredentials.h>
#include <cli/model/PasswordEncryptCredentials.h>
#include <cli/model/PasswordDecryptCredentials.h>
#include <cli/model/KeyEncryptCredentials.h>
#include <cli/model/KeyDecryptCredentials.h>

#include <cli/command/KeygenCommand.h>
#include <cli/command/KeyToPubCommand.h>
#include <cli/command/EncryptCommand.h>
#include <cli/command/DecryptCommand.h>

#include <cli/argument/validation/ArgumentValidationHub.h>

#include <cli/memory.h>

#include <istream>
#include <ostream>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <iterator>

using namespace cli;
using namespace cli::argument;
using namespace cli::argument::validation;
using namespace cli::command;
using namespace cli::model;

#undef IN
#undef OUT

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
    auto argument = argumentSource_->read(opt::CONTENT_INFO, ArgumentImportance::Optional);
    return !argument.isEmpty();
}

bool ArgumentIO::hasNoPassword() const {
    ULOG2(INFO) << "Check if password should be omitted.";
    auto argument = argumentSource_->read(opt::NO_PASSWORD, ArgumentImportance::Optional);
    ArgumentValidationHub::isBool()->validate(argument, ArgumentImportance::Optional);
    return argument.asValue().asOptionalBool();
}

bool ArgumentIO::isInteractive() const {
    ULOG2(INFO) << "Check if interactive mode is on.";
    auto argument = argumentSource_->read(opt::INTERACTIVE, ArgumentImportance::Optional);
    ArgumentValidationHub::isBool()->validate(argument, ArgumentImportance::Optional);
    return argument.asValue().asOptionalBool();
}

SecureValue ArgumentIO::getInput(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read input value.";
    auto argument = argumentSource_->read(opt::IN, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    return argumentValueSource_->readPassword(argument.asValue());
}

SecureValue ArgumentIO::getOutput(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read output value.";
    auto argument = argumentSource_->read(opt::OUT, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    return SecureValue(argument.asValue().value());
}

FileDataSource ArgumentIO::getInputSource(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read input source.";
    auto argument = argumentSource_->read(opt::IN, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    return getSource(argument.asValue());
}

FileDataSink ArgumentIO::getOutputSink(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read output destination.";
    auto argument = argumentSource_->read(opt::OUT, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    return getSink(argument.asValue());
}


FileDataSource ArgumentIO::getContentInfoSource(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read content info source.";
    auto argument = argumentSource_->read(opt::CONTENT_INFO, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    return getSource(argument.asValue());
}

FileDataSink ArgumentIO::getContentInfoSink(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read content info destination.";
    auto argument = argumentSource_->read(opt::CONTENT_INFO, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    return getSink(argument.asValue());
}

std::vector<std::unique_ptr<EncryptCredentials>>
ArgumentIO::getEncryptCredentials(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read recipients for encryption.";
    auto argument = argumentSource_->read(arg::RECIPIENT_ID, argumentImportance);
    argument.parse();
    auto validation = ArgumentValidationHub::isKeyValue();
    validation->setKeyValidation(ArgumentValidationHub::isEnum(arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_VALUES));
    validation->setValueValidation(ArgumentValidationHub::isNotEmpty());
    validation->validateList(argument, argumentImportance);
    std::vector<std::unique_ptr<EncryptCredentials>> result;
    for (const auto& argumentValue : argument.asList()) {
        auto credentials = readEncryptCredentials(argumentValue);
        result.insert(result.end(),
                std::make_move_iterator(credentials.begin()), std::make_move_iterator(credentials.end()));
    }
    return result;
}

std::vector<std::unique_ptr<DecryptCredentials>>
ArgumentIO::getDecryptCredentials(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read decryption credentials.";
    auto argument = argumentSource_->read(arg::KEYPASS, argumentImportance);
    argument.parse();
    auto validation = ArgumentValidationHub::isKeyValue();
    validation->setKeyValidation(ArgumentValidationHub::isEnum(arg::value::VIRGIL_DECRYPT_KEYPASS_VALUES));
    validation->setValueValidation(ArgumentValidationHub::isNotEmpty());
    validation->validateList(argument, argumentImportance);
    std::vector<std::unique_ptr<DecryptCredentials>> result;
    for (const auto& argumentValue : argument.asList()) {
        auto decryptCredentials = readDecryptCredentials(argumentValue);
        result.insert(result.end(),
                std::make_move_iterator(decryptCredentials.begin()), std::make_move_iterator(decryptCredentials.end()));
    }
    return result;
}

KeyAlgorithm ArgumentIO::getKeyAlgorithm(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read private key algorithm.";
    auto argument = argumentSource_->read(opt::ALGORITHM, argumentImportance);
    ArgumentValidationHub::isEnum(arg::value::VIRGIL_KEYGEN_ALG_VALUES)->validate(argument, argumentImportance);
    return argumentValueSource_->readKeyAlgorithm(argument.asValue());
}

PrivateKey ArgumentIO::getPrivateKey(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read private key.";
    auto argument = argumentSource_->read(opt::PRIVATE_KEY, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    auto privateKey = argumentValueSource_->readPrivateKey(argument.asValue());
    readPrivateKeyPassword(privateKey, argument.asValue(), opt::PRIVATE_KEY_PASSWORD);
    return std::move(privateKey);
}

PrivateKey ArgumentIO::getPrivateKeyFromInput(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read private key.";
    auto argument = argumentSource_->read(opt::IN, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    auto source = getSource(argument.asValue());
    PrivateKey privateKey(source.readAll(), Crypto::Bytes());
    readPrivateKeyPassword(privateKey, argument.asValue(), opt::PRIVATE_KEY_PASSWORD);
    return std::move(privateKey);
}

Password ArgumentIO::getKeyPassword(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read private key password.";
    auto argument = argumentSource_->readSecure(opt::PRIVATE_KEY_PASSWORD, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    return argumentValueSource_->readPassword(argument.asValue());
}

PublicKey ArgumentIO::getSenderKey(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read Sender's public key.";
    auto argument = argumentSource_->read(arg::RECIPIENT_ID, argumentImportance);
    argument.parse();
    auto validation = ArgumentValidationHub::isKeyValue();
    validation->setKeyValidation(ArgumentValidationHub::isEnum(arg::value::VIRGIL_VERIFY_RECIPIENT_ID_VALUES));
    validation->setValueValidation(ArgumentValidationHub::isNotEmpty());
    validation->validate(argument, argumentImportance);
    return readSenderKey(argument.asValue());
}

FileDataSource ArgumentIO::getSignatureSource(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read signature source.";
    auto argument = argumentSource_->read(opt::SIGN, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    return getSource(argument.asValue());
}

Crypto::Text ArgumentIO::getCommand(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read command.";
    auto argument = argumentSource_->read(arg::COMMAND, argumentImportance);
    ArgumentValidationHub::isEnum(arg::value::VIRGIL_COMMAND_VALUES)->validate(argument, argumentImportance);
    return Crypto::Text(argument.asValue().value());
}

CardIdentity ArgumentIO::getCardIdentity(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read Virgil Card identity.";
    auto argument = argumentSource_->read(arg::IDENTITY, argumentImportance);
    argument.parse();
    auto validation = ArgumentValidationHub::isKeyValue();
    validation->setKeyValidation(ArgumentValidationHub::isAny());
    validation->setValueValidation(ArgumentValidationHub::isNotEmpty());
    validation->validate(argument, argumentImportance);
    return CardIdentity(argument.asValue().value(), argument.asValue().key());
}

CardIdentityGroup ArgumentIO::getCardIdentityGroup(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read Virgil Card identities.";
    auto argument = argumentSource_->read(arg::IDENTITY, argumentImportance);
    argument.parse();
    ArgumentValidationHub::isNotEmpty()->validateList(argument, argumentImportance);
    CardIdentityGroup identityGroup;
    for (const auto argumentValue : argument.asList()) {
        identityGroup.append(argumentValue.value(), argumentValue.key());
    }
    return identityGroup;
}

Crypto::Text ArgumentIO::getCardScope(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read Virgil Card scope.";
    auto argument = argumentSource_->read(opt::SCOPE, argumentImportance);
    ArgumentValidationHub::isEnum(arg::value::VIRGIL_CARD_CREATE_SCOPE_VALUES)->validate(argument, argumentImportance);
    return argument.asValue().asString();
}

CardData ArgumentIO::getCardData(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read Virgil Card data.";
    auto argument = argumentSource_->read(opt::DATA, argumentImportance);
    argument.parse();
    auto validation = ArgumentValidationHub::isKeyValue();
    validation->setKeyValidation(ArgumentValidationHub::isNotEmpty());
    validation->setValueValidation(ArgumentValidationHub::isNotEmpty());
    validation->validateList(argument, argumentImportance);
    CardData cardData;
    for (const auto& argumentValue : argument.asList()) {
        cardData[argumentValue.key()] = argumentValue.value();
    }
    return cardData;
}

CardInfo ArgumentIO::getCardInfo(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read Virgil Card info.";
    auto argument = argumentSource_->read(opt::INFO, argumentImportance);
    argument.parse();
    auto validation = ArgumentValidationHub::isKeyValue();
    validation->setKeyValidation(ArgumentValidationHub::isEnum(arg::value::VIRGIL_CARD_CREATE_INFO_KEY_VALUES));
    validation->setValueValidation(ArgumentValidationHub::isNotEmpty());
    validation->validateList(argument, argumentImportance);
    std::string device;
    std::string deviceName;
    for (const auto& argumentValue : argument.asList()) {
        auto infoKey = argumentValue.key();
        if (infoKey == arg::value::VIRGIL_CARD_CREATE_INFO_KEY_DEVICE) {
            device = argumentValue.value();
        } else if (infoKey == arg::value::VIRGIL_CARD_CREATE_INFO_KEY_DEVICE_NAME) {
            deviceName = argumentValue.value();
        } else {
            throw error::ArgumentLogicError("Undefined key of the Virgil Card Info. Validation must fail first.");
        }
    }
    return CardInfo(device, deviceName);
}

SecureValue ArgumentIO::getAppAccessToken(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read Virgil Application Access Token.";
    auto argument = argumentSource_->readSecure(arg::value::VIRGIL_CONFIG_APP_ACCESS_TOKEN, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    return argumentValueSource_->readPassword(argument.asValue());
}

ApplicationCredentials ArgumentIO::getAppCredentials(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read Virgil Application Credentials (identifier, private key, private key password).";
    auto argumentAppKeyId = argumentSource_->readSecure(arg::value::VIRGIL_CONFIG_APP_KEY_ID, argumentImportance);
    auto argumentAppKeyData = argumentSource_->readSecure(arg::value::VIRGIL_CONFIG_APP_KEY_DATA, argumentImportance);
    ArgumentValidationHub::isText()->validate(argumentAppKeyId, argumentImportance);
    ArgumentValidationHub::isText()->validate(argumentAppKeyData, argumentImportance);
    auto appId = argumentValueSource_->readPassword(argumentAppKeyId.asValue());
    auto appKey = argumentValueSource_->readPrivateKey(argumentAppKeyData.asValue());
    readPrivateKeyPassword(appKey, argumentAppKeyData.asValue(), arg::value::VIRGIL_CONFIG_APP_KEY_PASSWORD);
    return ApplicationCredentials(std::move(appId), std::move(appKey));
}

Card ArgumentIO::getCardFromInput(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read Virgil Card from input.";
    auto argument = argumentSource_->read(opt::IN, argumentImportance);
    ArgumentValidationHub::isText()->validate(argument, argumentImportance);
    auto values = argumentValueSource_->readCards(argument.asValue());
    if (values.size() > 0) {
        return values[0];
    }
    throw error::ArgumentRuntimeError("Card was not read.");
}

CardRevocationReason ArgumentIO::getCardRevokeReason(ArgumentImportance argumentImportance) const {
    ULOG2(INFO) << "Read Virgil Card revocation reason.";
    auto argument = argumentSource_->read(opt::REVOCATION_REASON, argumentImportance);
    ArgumentValidationHub::isEnum(arg::value::VIRGIL_CARD_REVOKE_REASON_VALUES)->validate(argument, argumentImportance);
    return card_revocation_reason_from(argument.asValue().asString());
}


FileDataSource ArgumentIO::getSource(const ArgumentValue& argumentValue) const {
    if (argumentValue.isEmpty()) {
        ULOG3(INFO) << tfm::format("Read source is standard input.");
        return FileDataSource();
    } else {
        ULOG3(INFO) << tfm::format("Read source is file: '%s'.", argumentValue.value());
        return FileDataSource(argumentValue.value());
    }
}

FileDataSink ArgumentIO::getSink(const ArgumentValue& argumentValue) const {
    if (argumentValue.isEmpty()) {
        ULOG3(INFO) << tfm::format("Write destination is standard output.");
        return FileDataSink();
    } else {
        ULOG3(INFO) << tfm::format("Write destination is file: '%s'.", argumentValue.value());
        return FileDataSink(argumentValue.value());
    }
}

void ArgumentIO::readPrivateKeyPassword(
        PrivateKey& privateKey, const ArgumentValue& argumentValue, const char* passwordArgumentKey) const {
    ULOG2(INFO) << "Read private key password.";
    if (!privateKey.isEncrypted()) {
        return;
    }
    std::string passwordOption = passwordArgumentKey;
    do {
        LOG(INFO) << tfm::format("Read password for the private key: '%s'.", std::to_string(argumentValue));
        auto argument = argumentSource_->readSecure(passwordOption.c_str(), ArgumentImportance::Required);
        auto password = argumentValueSource_->readPassword(argument.asValue());
        if (privateKey.checkPassword(password)) {
            privateKey.setPassword(std::move(password));
            return;
        }
        passwordOption = argumentValue.value();
    } while (isInteractive());
    throw error::ArgumentRuntimeError(
            tfm::format("Wrong password for the private key '%s'.", std::to_string(argumentValue)));
}

std::vector<std::unique_ptr<EncryptCredentials>>
ArgumentIO::readEncryptCredentials(const ArgumentValue& argumentValue) const {
    LOG(INFO) << tfm::format("Read recipient(s) from the value: '%s'.", std::to_string(argumentValue));
    auto recipientType = argumentValue.key();
    std::vector<std::unique_ptr<EncryptCredentials>> result;
    if (recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_PASSWORD) {
        result.push_back(std::make_unique<PasswordEncryptCredentials>(
                argumentValueSource_->readPassword(argumentValue)
        ));
    } else if (recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_PUBKEY) {
        result.push_back(std::make_unique<KeyEncryptCredentials>(
                argumentValueSource_->readPublicKey(argumentValue)
        ));
    } else if (recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_VCARD ||
            recipientType == arg::value::VIRGIL_ENCRYPT_RECIPIENT_ID_EMAIL) {
        auto cards = argumentValueSource_->readCards(argumentValue);
        for (auto&& card : cards) {
            result.push_back(std::make_unique<KeyEncryptCredentials>(std::move(card)));
        }
    } else {
        throw error::ArgumentLogicError(
                tfm::format("Undefined key of the <%s>. Validation must fail first.", arg::RECIPIENT_ID));
    }
    return result;
}

std::vector<std::unique_ptr<DecryptCredentials>>
ArgumentIO::readDecryptCredentials(const ArgumentValue& argumentValue) const {
    LOG(INFO) << tfm::format("Read recipient(s) from the value: '%s'.", std::to_string(argumentValue));
    auto recipientType = argumentValue.key();
    std::vector<std::unique_ptr<DecryptCredentials>> result;
    if (recipientType == arg::value::VIRGIL_DECRYPT_KEYPASS_PASSWORD) {
        result.push_back(std::make_unique<PasswordDecryptCredentials>(
                argumentValueSource_->readPassword(argumentValue)
        ));
    } else if (recipientType == arg::value::VIRGIL_DECRYPT_KEYPASS_PRIVKEY) {
        auto privateKey = argumentValueSource_->readPrivateKey(argumentValue);
        readPrivateKeyPassword(privateKey, argumentValue, opt::PRIVATE_KEY_PASSWORD);
        result.push_back(std::make_unique<KeyDecryptCredentials>(std::move(privateKey)));
    } else {
        throw error::ArgumentLogicError(
                tfm::format("Undefined key of the <%s>. Validation must fail first.", arg::KEYPASS));
    }
    return result;
}

PublicKey ArgumentIO::readSenderKey(const ArgumentValue& argumentValue) const {
    LOG(INFO) << tfm::format("Read Sender's key from the value: '%s'.", std::to_string(argumentValue));
    if (argumentValue.key() == arg::value::VIRGIL_VERIFY_RECIPIENT_ID_PUBKEY) {
        return argumentValueSource_->readPublicKey(argumentValue);
    } else if (argumentValue.key() == arg::value::VIRGIL_VERIFY_RECIPIENT_ID_VCARD) {
        auto cards = argumentValueSource_->readCards(argumentValue);
        CHECK(cards.size() == 1);
        auto card = cards.front();
        return PublicKey(card.publicKeyData(), card.identifier());
    }
    throw error::ArgumentLogicError(
            tfm::format("Undefined key of the <%s>. Validation must fail first.", arg::RECIPIENT_ID));
}
