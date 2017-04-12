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

#include <cli/argument/ArgumentCommandLineSource.h>
#include <cli/argument/ArgumentConfigSource.h>

#include <cli/memory.h>
#include <cli/api/api.h>
#include <cli/api/Version.h>
#include <cli/io/Logger.h>
#include <cli/error/ArgumentError.h>
#include <cli/memory.h>

#include <cli/argument/validation/ArgumentValidationHub.h>
#include <cli/argument/internal/Argument_DocoptValue.h>

#include <docopt/docopt.h>

using cli::argument::Argument;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentCommandLineSource;
using cli::argument::ArgumentConfigSource;
using cli::argument::ArgumentRules;
using cli::argument::ArgumentImportance;
using cli::argument::validation::ArgumentValidationHub;

ArgumentCommandLineSource::ArgumentCommandLineSource(ArgumentCommandLineSource&&) = default;

ArgumentCommandLineSource& ArgumentCommandLineSource::operator=(ArgumentCommandLineSource&&) = default;

ArgumentCommandLineSource::~ArgumentCommandLineSource() noexcept = default;

namespace cli { namespace argument {
class ArgumentCommandLineSource::Impl {
public:
    std::vector<std::string> cmdArgs;
    std::map<std::string, docopt::value> docoptArgs;
    std::map<std::string, std::string> configArgs;

    std::unique_ptr<docopt::value> findValue(const char* argName) {
        { // First find in arguments
            auto value = docoptArgs.find(argName);
            if (value != docoptArgs.cend() && static_cast<bool>(value->second)) {
                return std::make_unique<docopt::value>(value->second);
            }
        }
        { // Second find in config overloads
            auto value = configArgs.find(argName);
            if (value != configArgs.cend()) {
                return std::make_unique<docopt::value>(value->second);
            }
        }
        return std::make_unique<docopt::value>();
    }
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

bool ArgumentCommandLineSource::doCanRead(const char* argName, ArgumentImportance) const {
    auto value = impl_->findValue(argName);
    return static_cast<bool>(*value);
}

void ArgumentCommandLineSource::doInit(const std::string& usage, const ArgumentParseOptions& usageOptions) {
    try {
        parseArguments(usage, usageOptions);
        processArguments();
    } catch (const docopt::DocoptArgumentError& error) {
        throw error::ArgumentParseError(error.what());
    } catch (const docopt::DocoptExitHelp&) {
        throw error::ArgumentShowUsageError();
    } catch (const docopt::DocoptExitVersion&) {
        throw error::ArgumentShowVersionError();
    }
}

void ArgumentCommandLineSource::doUpdateRules() {
    auto argumentInteractive = read(opt::INTERACTIVE, ArgumentImportance::Optional);
    auto argumentQuiet = read(opt::QUIET, ArgumentImportance::Optional);
    ArgumentValidationHub::isNumber()->validate(argumentInteractive, ArgumentImportance::Optional);
    ArgumentValidationHub::isNumber()->validate(argumentQuiet, ArgumentImportance::Optional);
    getArgumentRules()->allowUserInteraction(argumentInteractive.asValue().asOptionalBool());
    if (argumentQuiet.asValue().asOptionalBool()) {
        auto userLogger = el::Loggers::getLogger(kLoggerId_User);
        userLogger->configurations()->setGlobally(el::ConfigurationType::Enabled, "false");
        userLogger->reconfigure();
    }
}

Argument ArgumentCommandLineSource::doRead(const char* argName) const {
    return internal::argument_from(*impl_->findValue(argName));
}

void ArgumentCommandLineSource::parseArguments(const std::string& usage, const ArgumentParseOptions& usageOptions) {
    impl_->docoptArgs = docopt::docopt_parse(usage, impl_->cmdArgs, true, true, usageOptions.isOptionsFirst());
    for (auto const& arg : impl_->docoptArgs) {
        DLOG(INFO) << tfm::format("Found argument '%s' with value '%s'.", arg.first, arg.second);
    }
}

void ArgumentCommandLineSource::processArguments() {
    processConfigOverloads();
    processConfigSources();
}

void ArgumentCommandLineSource::processConfigOverloads() {
    auto configOverloads = internal::argument_from(impl_->docoptArgs[opt::D_SHORT]);
    for (auto& configValue : configOverloads.asList()) {
        configValue.parse();
        ArgumentValidationHub::isKeyValue()->validate(configValue);
        impl_->configArgs[configValue.key()] = configValue.value();
    }
    impl_->docoptArgs.erase(opt::D_SHORT);
}

void ArgumentCommandLineSource::processConfigSources() {
    auto configSources= internal::argument_from(impl_->docoptArgs[opt::C_SHORT]);
    for (auto& configFilePath : configSources.asList()) {
        ArgumentValidationHub::isText()->validate(configFilePath);
        this->insertSource(
                std::make_unique<ArgumentConfigSource>(configFilePath.asString())
        );
    }
    impl_->docoptArgs.erase(opt::C_SHORT);
}
