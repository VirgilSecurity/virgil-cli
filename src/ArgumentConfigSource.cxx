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

#include <cli/argument/ArgumentConfigSource.h>

#include <cli/memory.h>
#include <cli/io/Logger.h>
#include <cli/io/Path.h>
#include <cli/error/ArgumentError.h>
#include <cli/argument/internal/Argument_YamlNode.h>

#include <yaml-cpp/yaml.h>

using cli::argument::Argument;
using cli::argument::ArgumentConfigSource;
using cli::argument::ArgumentParseOptions;
using cli::error::ArgumentFileNotFound;
using cli::error::ArgumentValueError;
using cli::io::Path;

ArgumentConfigSource::ArgumentConfigSource(ArgumentConfigSource&&) = default;
ArgumentConfigSource& ArgumentConfigSource::operator=(ArgumentConfigSource&&) = default;
ArgumentConfigSource::~ArgumentConfigSource() noexcept = default;

namespace cli { namespace argument {

struct ArgumentConfigSource::Impl {
    Impl(const std::string& filePath) : configFilePath(filePath), config() {}
    std::string configFilePath;
    YAML::Node config;
};

}}

ArgumentConfigSource::ArgumentConfigSource(const std::string& configFilePath)
        : impl_(std::make_unique<ArgumentConfigSource::Impl>(configFilePath)) {
    if (!Path::existsFile(impl_->configFilePath)) {
        throw ArgumentFileNotFound(impl_->configFilePath);
    }
}

const char* ArgumentConfigSource::doGetName() const {
    return "ArgumentConfigSource";
}

void ArgumentConfigSource::doInit(const std::string& usage, const ArgumentParseOptions& usageOptions) {
    impl_->config = YAML::LoadFile(impl_->configFilePath);
}

void ArgumentConfigSource::doUpdateRules() {
    //TODO: Add configuration option that impact ArgumentRules
}

bool ArgumentConfigSource::doCanRead(const char* argName, ArgumentImportance argumentImportance) const {
    CHECK(impl_->config.IsDefined());
    return impl_->config[argName].IsDefined();
}

Argument ArgumentConfigSource::doRead(const char* argName) const {
    auto value = impl_->config[argName];
    CHECK(value.IsDefined());
    return internal::argument_from(value);
}
