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

#include <cli/command/SignCommand.h>

#include <cli/api/api.h>
#include <cli/crypto/Crypto.h>

#include <cli/io/Logger.h>
#include <cli/memory.h>

using cli::Crypto;
using cli::command::SignCommand;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentImportance;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentParseOptions;

const char* SignCommand::doGetName() const {
    return arg::value::VIRGIL_COMMAND_SIGN;
}

const char* SignCommand::doGetUsage() const {
    return usage::VIRGIL_SIGN;
}

ArgumentParseOptions SignCommand::doGetArgumentParseOptions() const {
    return ArgumentParseOptions().disableOptionsFirst();
}

void SignCommand::doProcess() const {

    ULOG1(INFO) << "Prepare input.";
    auto data = getArgumentIO()->getInputSource(ArgumentImportance::Optional);

    ULOG1(INFO) << "Read private key.";
    auto privateKey = getArgumentIO()->getPrivateKey(ArgumentImportance::Required);
    auto privateKeyPassword = std::make_unique<model::Password>();
    if (privateKey->isEncrypted()) {
        ULOG1(INFO) << "Read private key password.";
        privateKeyPassword = getArgumentIO()->getKeyPassword(ArgumentImportance::Required);
    }

    ULOG1(INFO) << "Sign input.";
    Crypto::StreamSigner signer;
    auto signature = signer.sign(*data, privateKey->key(), privateKeyPassword->password());

    ULOG1(INFO) << "Write signature to the output.";
    getArgumentIO()->getOutputSink(ArgumentImportance::Optional)->write(signature);
}
