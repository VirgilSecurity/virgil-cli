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
#include <cli/io/Logger.h>
#include <cli/argument/ArgumentParseOptions.h>

#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/sdk/VirgilSdkException.h>

#include <iostream>

using cli::argument::ArgumentIO;
using cli::argument::ArgumentSource;
using cli::command::Command;
using cli::argument::ArgumentParseOptions;

using virgil::crypto::VirgilCryptoException;
using virgil::crypto::VirgilCryptoError;
using virgil::sdk::VirgilSdkException;

static std::string buildErrorMessage(const VirgilCryptoException& exception) {
    if (exception.condition().category() == virgil::crypto::crypto_category()) {
        switch(static_cast<VirgilCryptoError>(exception.condition().value())) {
            case VirgilCryptoError::NotFoundPasswordRecipient:
                return "Recipient password mismatch.";
            default:
                break;
        }
    }
    if (VLOG_IS_ON(1)) {
        return exception.what();
    } else {
        return exception.condition().message();
    }
}

static std::string buildErrorMessage(const VirgilSdkException& exception) {
    std::string message(exception.what());
    if (message.find("HTTP Code: 404") != std::string::npos) {
        //TODO: Change this hot-fix when service will support informative message for this case.
        return exception.condition().message() + " Requested entity is not found.";
    } else {
        return exception.what();
    }
}

Command::Command(std::shared_ptr<argument::ArgumentIO> argumentIO) : argumentIO_(argumentIO) {
    DCHECK(argumentIO_);
}

const char* Command::getName() const {
    return doGetName();
}

const char* Command::getUsage() const {
    return doGetUsage();
}

std::shared_ptr<ArgumentIO> Command::getArgumentIO() const {
    return argumentIO_;
}

ArgumentParseOptions Command::getArgumentParseOptions() const {
    return doGetArgumentParseOptions();
}

void Command::process() {
    LOG(INFO) << "Start process command:" << getName();
    try {
        getArgumentIO()->configureUsage(getUsage(), getArgumentParseOptions());
        doProcess();
    } catch (const error::ArgumentShowUsageError&) {
        showUsage();
    } catch (const error::ArgumentShowVersionError&) {
        showVersion();
    } catch (const error::ArgumentRuntimeError& error) {
        showUsage(error.what());
    } catch (const VirgilCryptoException& exception) {
        LOG(FATAL) << exception.what();
        showUsage(buildErrorMessage(exception).c_str());
    } catch (const VirgilSdkException& exception) {
        LOG(FATAL) << exception.what();
        showUsage(buildErrorMessage(exception).c_str());
    }
}

void Command::showUsage(const char* errorMessage) const {
    if (errorMessage != nullptr && strlen(errorMessage) != 0) {
        ULOG(FATAL) << errorMessage;
        if (VLOG_IS_ON(1)) {
            std::cout << getUsage();
        }
        throw error::ExitFailure();
    }
    std::cout << getUsage();
}

void Command::showVersion() const {
    std::cout << api::Version::cliVersion();
}
