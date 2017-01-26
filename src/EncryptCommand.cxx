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

#include <cli/command/EncryptCommand.h>

#include <cli/api/api.h>
#include <cli/crypto/Crypto.h>
#include <cli/io/Logger.h>

using cli::Crypto;
using cli::command::EncryptCommand;
using cli::argument::ArgumentImportance;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentParseOptions;

const char* EncryptCommand::doGetName() const {
    return arg::value::VIRGIL_COMMAND_ENCRYPT;
}

const char* EncryptCommand::doGetUsage() const {
    return usage::VIRGIL_ENCRYPT;
}

ArgumentParseOptions EncryptCommand::doGetArgumentParseOptions() const {
    return ArgumentParseOptions().disableOptionsFirst();
}


void EncryptCommand::doProcess() const {
    ULOG2(INFO) << "Read parameters.";
    auto input = getArgumentIO()->getInputSource(ArgumentImportance::Optional);
    auto output = getArgumentIO()->getOutputSink(ArgumentImportance::Optional);

    bool doWriteContentInfo = getArgumentIO()->hasContentInfo();
    bool embedContentInfo = !doWriteContentInfo;

    ULOG2(INFO) << "Add recipients to the cipher.";
    Crypto::StreamCipher cipher;
    auto encryptCredentials = getArgumentIO()->getEncryptCredentials(ArgumentImportance::Required);
    for (const auto& credential : encryptCredentials) {
        credential->addSelfTo(cipher);
    }

    ULOG2(INFO) << "Encrypt data.";
    cipher.encrypt(input, output, embedContentInfo);

    if (doWriteContentInfo) {
        ULOG2(INFO) << "Write content info.";
        getArgumentIO()->getContentInfoSink(ArgumentImportance::Required).write(cipher.getContentInfo());
    }
}
