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

#include <cli/argument/ArgumentCommandLineSource.h>

#include <cli/memory.h>
#include <cli/api/api.h>
#include <cli/api/Version.h>
#include <cli/error/ArgumentError.h>
#include <cli/io/Logger.h>

#include <docopt/docopt.h>

using cli::argument::Argument;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentCommandLineSource;
using cli::argument::ArgumentRules;
using cli::argument::ArgumentImportance;

ArgumentCommandLineSource::ArgumentCommandLineSource(ArgumentCommandLineSource&&) = default;

ArgumentCommandLineSource& ArgumentCommandLineSource::operator=(ArgumentCommandLineSource&&) = default;

ArgumentCommandLineSource::~ArgumentCommandLineSource() noexcept = default;

namespace cli { namespace argument {
class ArgumentCommandLineSource::Impl {
public:
    std::vector<std::string> cmdArgs;
    std::map<std::string, docopt::value> docoptArgs;
};
}}

static std::vector<std::string> args_to_str_list(const char* argv_start[], const char* argv_end[]) {
    std::vector<std::string> result;
    for (auto argv = argv_start; argv < argv_end; ++argv) {
        result.push_back(std::string(*argv));
    }
    return result;
}

ArgumentCommandLineSource::ArgumentCommandLineSource(const std::vector<std::string>& args)
        : impl_(std::make_unique<Impl>()) {
    impl_->cmdArgs = args;
}

ArgumentCommandLineSource::ArgumentCommandLineSource(const char* argvStart[], const char* argvEnd[])
        : impl_(std::make_unique<Impl>()) {
    impl_->cmdArgs = args_to_str_list(argvStart, argvEnd);
}

const char* ArgumentCommandLineSource::doGetName() const {
    return "ArgumentCommandLineSource";
}

bool ArgumentCommandLineSource::doCanRead(const char* argName, ArgumentImportance argumentImportance) const {
    auto value = impl_->docoptArgs.find(argName);
    return value != impl_->docoptArgs.cend() && static_cast<bool>(value->second);
}

void ArgumentCommandLineSource::doInit(const std::string& usage, const ArgumentParseOptions& usageOptions) {
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

void ArgumentCommandLineSource::doUpdateRules() {
    getArgumentRules()->allowUserInteraction(read(opt::INTERACTIVE, ArgumentImportance::Optional).asBool());
    if (read(opt::QUIET, ArgumentImportance::Optional).asBool()) {
        auto userLogger = el::Loggers::getLogger(kLoggerId_User);
        userLogger->configurations()->setGlobally(el::ConfigurationType::Enabled, "false");
        userLogger->reconfigure();
    }
}

Argument ArgumentCommandLineSource::doRead(const char* argName) const {
    return impl_->docoptArgs[argName];
}
