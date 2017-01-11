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

#include <cli/argument/InteractiveArgumentSource.h>

#include <cli/api/api.h>
#include <cli/api/Version.h>
#include <cli/error/ArgumentError.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <cli/logger/Logger.h>

#include <docopt/docopt.h>

using cli::argument::ArgumentSource;
using cli::argument::InteractiveArgumentSource;

using UsageOptions = cli::argument::ArgumentSource::UsageOptions;

using BytesUtils = virgil::crypto::VirgilByteArrayUtils;


InteractiveArgumentSource::InteractiveArgumentSource(std::shared_ptr<cmd::CommandPrompt> cmd)
        : cmd_(cmd) {
}

const char* InteractiveArgumentSource::doGetName() const {
    return "InteractiveArgumentSource";
}

void InteractiveArgumentSource::doInit(const std::string& usage, const UsageOptions& usageOptions) const {
    cmd_->init(usage);
}

void InteractiveArgumentSource::doUpdateRules(std::shared_ptr<ArgumentRules> argumentRules) const {
    (void) argumentRules;
}

bool InteractiveArgumentSource::doCanRead(const char* argName, ArgumentImportance argumentImportance) const {
    (void)argName;
    switch (argumentImportance) {
        case ArgumentImportance::Required:
            return argumentRules()->allowUserInteraction();
        case ArgumentImportance::Optional:
            return argumentRules()->allowUserInteraction() &&
                    argumentRules()->allowUserInteractionForOptionalArguments();
    }
}

std::string InteractiveArgumentSource::doReadString(const char* argName) const {
    return cmd_->readString(argName);
}

bool InteractiveArgumentSource::doReadBool(const char* argName) const {
    return cmd_->readBool(argName);
}

int InteractiveArgumentSource::doReadInt(const char* argName) const {
    return cmd_->readInt(argName);
}

std::vector<std::string> InteractiveArgumentSource::doReadStringList(const char* argName) const {
    return cmd_->readStringList(argName);
}
