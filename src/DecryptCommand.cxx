/**
 * Copyright (C) 2015-2017 Virgil Security Inc.
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

#include <cli/command/DecryptCommand.h>

#include <cli/api/api.h>
#include <cli/crypto/Crypto.h>
#include <cli/io/Logger.h>
#include <cli/error/ArgumentError.h>

using cli::Crypto;
using cli::command::DecryptCommand;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentImportance;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentParseOptions;

const char* DecryptCommand::doGetName() const {
    return arg::value::VIRGIL_COMMAND_DECRYPT;
}

const char* DecryptCommand::doGetUsage() const {
    return usage::VIRGIL_DECRYPT;
}

ArgumentParseOptions DecryptCommand::doGetArgumentParseOptions() const {
    return ArgumentParseOptions().disableOptionsFirst();
}

void DecryptCommand::doProcess() const {
    ULOG1(INFO)  << "Read parameters.";
    auto input = getArgumentIO()->getInputSource(ArgumentImportance::Optional);
    auto output = getArgumentIO()->getOutputSink(ArgumentImportance::Optional);
    bool hasContentInfo = getArgumentIO()->hasContentInfo();
    auto recipients = getArgumentIO()->getDecryptCredentials(ArgumentImportance::Required);

    Crypto::StreamCipher cipher;
    if (hasContentInfo) {
        auto contentInfo = getArgumentIO()->getContentInfoSource(ArgumentImportance::Required).readAll();
        ULOG1(INFO)  << "Set content info.";
        cipher.setContentInfo(contentInfo);
    }

    ULOG1(INFO)  << "Decrypt and write to the output.";
    bool decrypted = false;
    for (const auto& recipient : recipients) {
        decrypted = recipient->decrypt(cipher, input, output);
        if (decrypted){
            break;
        }
    }
    if (!decrypted) {
        throw error::ArgumentRecipientDecryptionError();
    }
}
