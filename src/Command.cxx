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

#include <cli/command/Command.h>

#include <cli/error/ArgumentError.h>
#include <cli/error/ExitError.h>
#include <cli/api/Version.h>
#include <cli/logger/Logger.h>

#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/sdk/VirgilSdkException.h>

#include <iostream>

using cli::command::Command;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentIO;

using virgil::crypto::VirgilCryptoException;
using virgil::sdk::VirgilSdkException;

const char* Command::getName() const {
    return doGetName();
}

const char* Command::getUsage() const {
    return doGetUsage();
}

std::shared_ptr<ArgumentIO> Command::getArgumentIO() const {
    return std::make_shared<ArgumentIO>();
}

ArgumentSource::UsageOptions Command::getUsageOptions() const {
    return doGetUsageOptions();
}

void Command::process(std::unique_ptr<argument::ArgumentSource> args) const {
    DLOG(INFO) << "Start process command:" << getName();
    try {
        args->init(getUsage(), getUsageOptions());
        doProcess(std::move(args));
    } catch (const error::ArgumentShowUsageError&) {
        showUsage();
    } catch (const error::ArgumentShowVersionError&) {
        showVersion();
    } catch (const error::ArgumentRuntimeError& error) {
        ULOG(0, FATAL) << error.what();
        if (VLOG_IS_ON(1)) {
            showUsage();
        }
        throw error::ExitFailure();
    } catch (const VirgilCryptoException& exception) {
        LOG(FATAL) << exception.what();
        ULOG(0, FATAL) << exception.condition().message();
        if (VLOG_IS_ON(1)) {
            showUsage();
        }
        throw error::ExitFailure();
    } catch (const VirgilSdkException& exception) {
        LOG(FATAL) << exception.what();
        ULOG(0, FATAL) << exception.condition().message() << "See log file for details.";
        if (VLOG_IS_ON(1)) {
            showUsage();
        }
        throw error::ExitFailure();
    }
}

void Command::showUsage(const char* errorMessage) const {
    std::ostream* out = &std::cout;
    if (errorMessage != nullptr) {
        out = &std::cerr;
        *out << tfm::format("%s\n", errorMessage);
    }
    *out << tfm::format("%s\n", getUsage());
}

void Command::showVersion() const {
    std::cout << api::Version::cliVersion();
}
