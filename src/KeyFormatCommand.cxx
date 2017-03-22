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

#include <cli/command/KeyFormatCommand.h>

#include <cli/api/api.h>
#include <cli/crypto/Crypto.h>

#include <cli/io/Logger.h>
#include <cli/memory.h>
#include <cli/error/ArgumentError.h>

using cli::Crypto;
using cli::command::KeyFormatCommand;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentImportance;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentParseOptions;
using cli::model::Password;
using cli::model::PrivateKey;
using cli::error::ArgumentLogicError;

const char* KeyFormatCommand::doGetName() const {
    return arg::value::VIRGIL_COMMAND_KEY_FORMAT;
}

const char* KeyFormatCommand::doGetUsage() const {
    return usage::VIRGIL_KEY_FORMAT;
}

ArgumentParseOptions KeyFormatCommand::doGetArgumentParseOptions() const {
    return ArgumentParseOptions().disableOptionsFirst();
}

void KeyFormatCommand::doProcess() const {
    ULOG1(INFO) << "Read arguments.";

    auto isPublicKey = getArgumentIO()->isPublicKey();
    auto isPrivateKey = getArgumentIO()->isPrivateKey();

    if (isPublicKey) {
        processPublicKey();
    } else if (isPrivateKey) {
        processPrivateKey();
    } else {
        throw ArgumentLogicError("Key format is not given in the command arguments.");
    }
}

void KeyFormatCommand::processPublicKey() const {
    auto publicKeySource = getArgumentIO()->getInputSource(ArgumentImportance::Required);
    auto format = getArgumentIO()->getKeyFormat(ArgumentImportance::Required);

    ULOG1(INFO) << "Format public key.";
    Crypto::Bytes formattedKey;
    if (format == arg::value::VIRGIL_KEY_FORMAT_KEY_FORMAT_PEM) {
        formattedKey = Crypto::KeyPair::publicKeyToPEM(publicKeySource.readAll());
    } else if (format == arg::value::VIRGIL_KEY_FORMAT_KEY_FORMAT_DER) {
        formattedKey = Crypto::KeyPair::publicKeyToDER(publicKeySource.readAll());
    } else {
        throw ArgumentLogicError("Unexpected key format is given. Validation should fail first.");
    }
    ULOG1(INFO) << "Write public key to the output.";
    getArgumentIO()->getOutputSink(ArgumentImportance::Optional).write(formattedKey);

}

void KeyFormatCommand::processPrivateKey() const {
    auto privateKey = getArgumentIO()->getPrivateKeyFromInput(ArgumentImportance::Required);
    auto format = getArgumentIO()->getKeyFormat(ArgumentImportance::Required);

    ULOG1(INFO) << "Format private key.";
    Crypto::Bytes formattedKey;
    if (format == arg::value::VIRGIL_KEY_FORMAT_KEY_FORMAT_PEM) {
        formattedKey = Crypto::KeyPair::privateKeyToPEM(privateKey.key(), privateKey.password().bytesValue());
    } else if (format == arg::value::VIRGIL_KEY_FORMAT_KEY_FORMAT_DER) {
        formattedKey = Crypto::KeyPair::privateKeyToDER(privateKey.key(), privateKey.password().bytesValue());
    } else {
        throw ArgumentLogicError("Unexpected key format is given. Validation should fail first.");
    }
    ULOG1(INFO) << "Write private key to the output.";
    getArgumentIO()->getOutputSink(ArgumentImportance::Optional).write(formattedKey);
}
