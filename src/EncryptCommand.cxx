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
#include <cli/logger/Logger.h>
#include <cli/model/Recipient.h>

using cli::command::EncryptCommand;
using cli::argument::ArgumentIO;
using cli::Crypto;

using UsageOptions = cli::argument::ArgumentSource::UsageOptions;

const char* EncryptCommand::getName() {
    return arg::value::VIRGIL_COMMAND_ENCRYPT;
}

const char* EncryptCommand::doGetName() const {
    return EncryptCommand::getName();
}

const char* EncryptCommand::doGetUsage() const {
    return usage::VIRGIL_ENCRYPT;
}

UsageOptions EncryptCommand::doGetUsageOptions() const {
    return UsageOptions().disableOptionsFirst();
}


void EncryptCommand::doProcess(std::unique_ptr<argument::ArgumentSource> args) const {
    ULOG(2, INFO) << "Read parameters.";
    auto input = getArgumentIO()->getInput(args)->transform();
    auto output = getArgumentIO()->getOutput(args)->transform();
    bool doWriteContentInfo = getArgumentIO()->hasContentInfo(args);
    bool embedContentInfo = !doWriteContentInfo;
    auto serviceClient = getArgumentIO()->getClient(args)->transform();

    ULOG(2, INFO) << "Add recipients to the cipher.";
    Crypto::StreamCipher cipher;
    auto recipients = getArgumentIO()->getRecipient(args)->transform();
    for (const auto& recipient : recipients) {
        recipient->addSelfTo(cipher, *serviceClient);
    }

    ULOG(2, INFO) << "Encrypt data.";
    cipher.encrypt(*input, *output, embedContentInfo);

    if (doWriteContentInfo) {
        ULOG(2, INFO) << "Write content info.";
        getArgumentIO()->getContentInfoOutput(args)->transform()->write(cipher.getContentInfo());
    }
}
