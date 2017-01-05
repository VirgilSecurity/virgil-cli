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

#include <cli/command/KeyToPubCommand.h>

#include <cli/api/api.h>
#include <cli/logger/Logger.h>

#include <virgil/crypto/VirgilKeyPair.h>

using cli::command::KeyToPubCommand;
using cli::argument::ArgumentIO;

using UsageOptions = cli::argument::ArgumentSource::UsageOptions;
using KeyPair = virgil::crypto::VirgilKeyPair;

const char* KeyToPubCommand::getName() {
    return arg::value::VIRGIL_COMMAND_KEY2PUB;
}

const char* KeyToPubCommand::doGetName() const {
    return KeyToPubCommand::getName();
}

const char* KeyToPubCommand::doGetUsage() const {
    return usage::VIRGIL_KEY2PUB;
}

UsageOptions KeyToPubCommand::doGetUsageOptions() const {
    return UsageOptions().disableOptionsFirst();
}

void KeyToPubCommand::doProcess(std::unique_ptr<argument::ArgumentSource> args) const {
    ULOG(1, INFO) << "Read private key.";
    auto privateKey = getArgumentIO()->readInput(args);
    ArgumentIO::Bytes pwd;
    if (KeyPair::isPrivateKeyEncrypted(privateKey)) {
        pwd = getArgumentIO()->readKeyPassword(args);
    }
    ULOG(1, INFO) << "Extract public key.";
    auto publicKey = KeyPair::extractPublicKey(privateKey, pwd);
    ULOG(1, INFO) << "Write public key.";
    getArgumentIO()->writeOutput(args, publicKey);
}
