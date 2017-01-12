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

#include <cli/argument/CommandArgumentSource.h>

#include <cli/api/api.h>
#include <cli/api/Version.h>
#include <cli/error/ArgumentError.h>
#include <cli/logger/Logger.h>

#include <docopt/docopt.h>

using cli::argument::ArgumentSource;
using cli::argument::CommandArgumentSource;
using cli::argument::ArgumentRules;
using cli::argument::ArgumentImportance;

CommandArgumentSource::CommandArgumentSource(CommandArgumentSource&&) {
        DLOG(INFO) << "Move constructor command argument source.";
}

CommandArgumentSource& CommandArgumentSource::operator=(CommandArgumentSource&&) {
        DLOG(INFO) << "Move assignment command argument source.";
        return *this;
}

CommandArgumentSource::~CommandArgumentSource() noexcept = default;

namespace cli { namespace argument {
class CommandArgumentSource::Impl {
public:
    std::vector<std::string> cmdArgs;
    std::map<std::string, docopt::value> docoptArgs;
};
}}

static std::vector<std::string> args_to_str_list(char* argv_start[], char* argv_end[]) {
    std::vector<std::string> result;
    for (auto argv = argv_start; argv < argv_end; ++argv) {
        result.push_back(std::string(*argv));
    }
    return result;
}

CommandArgumentSource::CommandArgumentSource(const std::vector<std::string>& args)
        : impl_(std::make_unique<Impl>()) {
    impl_->cmdArgs = args;
}

CommandArgumentSource::CommandArgumentSource(char** argvStart, char** argvEnd)
        : impl_(std::make_unique<Impl>()) {
    impl_->cmdArgs = args_to_str_list(argvStart, argvEnd);
}

const char* CommandArgumentSource::doGetName() const {
    return "CommandArgumentSource";
}

bool CommandArgumentSource::doCanRead(const char* argName, ArgumentImportance argumentImportance) const {
    DLOG(INFO) << tfm::format(
            "Search argument: '%s' (%s), in the command line options.", argName, std::to_string(argumentImportance));
    auto value = impl_->docoptArgs.find(argName);
    DLOG(INFO) << tfm::format(
            "Search status: %s.", value != std::cend(impl_->docoptArgs) ? "success" : "failed");
    return value != std::cend(impl_->docoptArgs) && static_cast<bool>(value->second);
}

void CommandArgumentSource::doInit(const std::string& usage, const UsageOptions& usageOptions) const {
    try {
        impl_->docoptArgs = docopt::docopt_parse(usage, impl_->cmdArgs, true, true, usageOptions.isOptionsFirst());
    } catch (const docopt::DocoptArgumentError& error) {
        throw error::ArgumentParseError(error.what());
    } catch (const docopt::DocoptExitHelp&) {
        throw error::ArgumentShowUsageError();
    } catch (const docopt::DocoptExitVersion&) {
        throw error::ArgumentShowVersionError();
    }
}

void CommandArgumentSource::doUpdateRules(std::shared_ptr<ArgumentRules> argumentRules) const {
    argumentRules->allowUserInteraction(doReadBool(opt::INTERACTIVE));
    if (doReadBool(opt::QUIET)) {
        auto userLogger = el::Loggers::getLogger(kLoggerId_User);
        userLogger->configurations()->setGlobally(el::ConfigurationType::Enabled, "false");
        userLogger->reconfigure();
    }
}

std::string CommandArgumentSource::doReadString(const char* argName) const {
    auto value = impl_->docoptArgs[argName];
    if (value.isString()) {
        return value.asString();
    } else if (!value) {
        return std::string();
    } else {
        throw error::ArgumentTypeError(argName, "string");
    }
}

bool CommandArgumentSource::doReadBool(const char* argName) const {
    auto value = impl_->docoptArgs[argName];
    if (value.isBool()) {
        return value.asBool();
    } else if (!value) {
        return false;
    } else {
        throw error::ArgumentTypeError(argName, "boolean");
    }
}

int CommandArgumentSource::doReadInt(const char* argName) const {
    auto value = impl_->docoptArgs[argName];
    if (value.isLong()) {
        return static_cast<int>(value.asLong());
    } else if (!value) {
        return 0;
    } else {
        throw error::ArgumentTypeError(argName, "number");
    }
}

std::vector<std::string> CommandArgumentSource::doReadStringList(const char* argName) const {
    auto value = impl_->docoptArgs[argName];
    if (value.isStringList()) {
        return value.asStringList();
    } else if (!value) {
        return std::vector<std::string>();
    } else {
        throw error::ArgumentTypeError(argName, "string list");
    }
}
