/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#include <cli/memory.h>
#include <cli/api/Configurations.h>

#include <cli/cmd/StandardCommandPrompt.h>
#include <cli/argument/ArgumentRules.h>
#include <cli/argument/ArgumentIO.h>
#include <cli/argument/ArgumentSource.h>
#include <cli/argument/ArgumentCommandLineSource.h>
#include <cli/argument/ArgumentUserInputSource.h>
#include <cli/argument/ArgumentDefaultsSource.h>
#include <cli/argument/ArgumentConfigSource.h>
#include <cli/argument/ArgumentValueSource.h>
#include <cli/argument/ArgumentValueFileSource.h>
#include <cli/argument/ArgumentValueVirgilSource.h>
#include <cli/argument/ArgumentValueTextSource.h>
#include <cli/argument/ArgumentValueEnumSource.h>
#include <cli/command/HubCommand.h>

#include <cli/error/ArgumentError.h>
#include <cli/error/ExitError.h>
#include <cli/io/Logger.h>

#include <cstdlib>

INITIALIZE_EASYLOGGINGPP

using cli::argument::ArgumentRules;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentValueSource;
using cli::argument::ArgumentCommandLineSource;
using cli::argument::ArgumentConfigSource;
using cli::argument::ArgumentDefaultsSource;
using cli::argument::ArgumentUserInputSource;
using cli::argument::ArgumentValueSource;
using cli::argument::ArgumentValueFileSource;
using cli::argument::ArgumentValueVirgilSource;
using cli::argument::ArgumentValueEnumSource;
using cli::argument::ArgumentValueTextSource;
using cli::cmd::StandardCommandPrompt;
using cli::command::Command;
using cli::command::HubCommand;
using cli::error::ExitFailure;
using cli::error::ExitSuccess;

std::unique_ptr<Command> createRootCommand(int argc, const char* argv[]);

int main(int argc, const char* argv[]) {
    try {
        cli::Configurations::init();
        cli::Configurations::apply(argc, argv);

        LOG(INFO) << "Start application.";
        LOG(INFO) << "Verbose level:" << el::Loggers::verboseLevel();

        createRootCommand(argc, argv)->process();
    } catch (const ExitFailure&) {
        // Was handled in-place, was rethrown for exit
        return EXIT_FAILURE;
    } catch (const ExitSuccess&) {
        // Was handled in-place, was rethrown for exit
        return EXIT_SUCCESS;
    } catch (const std::exception& exception) {
        LOG(FATAL) << exception.what();
        ULOG(FATAL) << "Unexpected error occurred. Contact support for help.";
        return EXIT_FAILURE;
    } catch (...) {
        ULOG(FATAL) << "Undefined error occurred. Contact support for help.";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

std::unique_ptr<ArgumentSource> createArgumentSource(int argc, const char* argv[]) {
    auto commandArgumentSource = std::make_unique<ArgumentCommandLineSource>(argv + 1, argv + argc);
    commandArgumentSource->
            appendSource(std::make_unique<ArgumentConfigSource>(cli::Configurations::getDefaultConfigFilePath()))->
            appendSource(std::make_unique<ArgumentDefaultsSource>())->
            appendSource(std::make_unique<ArgumentUserInputSource>(std::make_unique<StandardCommandPrompt>()));

    commandArgumentSource->setupRules(std::make_unique<ArgumentRules>());
    return std::move(commandArgumentSource);
}

std::unique_ptr<ArgumentValueSource> createArgumentValueSource() {
    auto argumentValueSource = std::make_unique<ArgumentValueFileSource>();
    argumentValueSource->appendSource(
            std::make_unique<ArgumentValueVirgilSource>()
    )->appendSource(
            std::make_unique<ArgumentValueEnumSource>()
    )->appendSource(
            std::make_unique<ArgumentValueTextSource>()
    );
    return std::move(argumentValueSource);
}

std::unique_ptr<ArgumentValueSource> createArgumentValueLocalSource() {
    auto argumentValueSource = std::make_unique<ArgumentValueFileSource>();
    argumentValueSource->appendSource(
            std::make_unique<ArgumentValueEnumSource>()
    )->appendSource(
            std::make_unique<ArgumentValueTextSource>()
    );
    return std::move(argumentValueSource);
}

std::unique_ptr<ArgumentIO> createArgumentIO(int argc, const char* argv[]) {
    return std::make_unique<ArgumentIO>(
            createArgumentSource(argc, argv), createArgumentValueSource(), createArgumentValueLocalSource()
    );
}

std::unique_ptr<Command> createRootCommand(int argc, const char* argv[]) {
    return std::make_unique<HubCommand>(createArgumentIO(argc, argv));
}
