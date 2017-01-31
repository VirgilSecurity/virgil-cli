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

#include <cli/argument/ArgumentUserInputSource.h>

#include <cli/api/api.h>
#include <cli/api/Version.h>
#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>
#include <cli/crypto/Crypto.h>

#include <docopt/docopt.h>

using cli::argument::Argument;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentUserInputSource;
using cli::argument::ArgumentRules;
using cli::argument::ArgumentImportance;
using cli::cmd::CommandPrompt;

using ArgumentParseOptions = cli::argument::ArgumentParseOptions;


ArgumentUserInputSource::ArgumentUserInputSource(std::shared_ptr<CommandPrompt> cmd) : cmd_(cmd) {
}

const char* ArgumentUserInputSource::doGetName() const {
    return "ArgumentUserInputSource";
}

void ArgumentUserInputSource::doInit(const std::string& usage, const ArgumentParseOptions& usageOptions) {
    cmd_->init(usage);
}

void ArgumentUserInputSource::doUpdateRules() {
    // Do nothing
}

bool ArgumentUserInputSource::doCanRead(const char* argName, ArgumentImportance argumentImportance) const {
    (void)argName;
    switch (argumentImportance) {
        case ArgumentImportance::Required:
            return getArgumentRules()->allowUserInteraction();
        case ArgumentImportance::Optional:
            return getArgumentRules()->allowUserInteraction() &&
                    getArgumentRules()->allowUserInteractionForOptionalArguments();
    }
}

Argument ArgumentUserInputSource::doRead(const char* argName) const {
    return Argument(cmd_->readString(argName));
}
