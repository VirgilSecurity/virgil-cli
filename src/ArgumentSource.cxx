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

#include <cli/argument/ArgumentSource.h>

#include <cli/error/ArgumentError.h>
#include <cli/logger/Logger.h>

#undef IN
#undef OUT

using cli::argument::ArgumentSource;
using cli::argument::ArgumentRules;
using cli::argument::ArgumentImportance;
using UsageOptions = cli::argument::ArgumentSource::UsageOptions;

UsageOptions& UsageOptions::enableOptionsFirst() {
    optionsFirst_ = true;
    return *this;
}

UsageOptions& UsageOptions::disableOptionsFirst() {
    optionsFirst_ = false;
    return *this;
}

bool UsageOptions::isOptionsFirst() const {
    return optionsFirst_;
}

UsageOptions UsageOptions::clone() const {
    return *this;
}

const char* ArgumentSource::getName() const {
    return doGetName();
}


namespace cli { namespace argument {

template<typename T>
class ArgumentSource::ArgumentReadHelper {
public:
    ArgumentReadHelper(const ArgumentSource* thisSource) : thisSource_(thisSource) {
        DLOG(TRACE);
        DLOG(INFO) << tfm::format("ArgumentReadHelper::ArgumentReadHelper(%s)", thisSource);
        DCHECK(thisSource_ != nullptr);
    }

    T read(const char* argName, ArgumentImportance argImportance) const {
        DLOG(INFO) << tfm::format("Search source for argument: '%s' (%s)", argName, std::to_string(argImportance));
        for (auto source = thisSource_; source != nullptr; source = source->nextSource_.get()) {
            DLOG(INFO) << "Ask source:" << source->getName();
            if (source->doCanRead(argName, argImportance)) {
                DLOG(INFO) << "Read from the source:" << source->getName();
                DLOG(INFO) << tfm::format("Read argument: '%s' (%s)", argName, std::to_string(argImportance));
                return doRead(source, argName);
            }
        }
        switch (argImportance) {
            case ArgumentImportance::Required:
                LOG(ERROR) << tfm::format("Required argument '%s' is not defined.", argName);
                throw error::ArgumentNotFoundError(argName);
            case ArgumentImportance::Optional:
                LOG(WARNING) << tfm::format("Optional argument '%s' is not defined. Return empty value.", argName);
                return T();
        }
    }

private:
    static T doRead(const ArgumentSource* source, const char* argName);

private:
    const ArgumentSource* thisSource_;
};

template<>
std::string ArgumentSource::ArgumentReadHelper<std::string>::doRead(const ArgumentSource* source, const char* argName) {
    return source->doReadString(argName);
}

template<>
std::vector<std::string> ArgumentSource::ArgumentReadHelper<std::vector<std::string>>::doRead(
        const ArgumentSource* source, const char* argName) {
    return source->doReadStringList(argName);
}

template<>
bool ArgumentSource::ArgumentReadHelper<bool>::doRead(const ArgumentSource* source, const char* argName) {
    return source->doReadBool(argName);
}

template<>
int ArgumentSource::ArgumentReadHelper<int>::doRead(const ArgumentSource* source, const char* argName) {
    return source->doReadInt(argName);
}

}}

ArgumentSource* ArgumentSource::setNextSource(std::shared_ptr<ArgumentSource> source) {
    DLOG(INFO) << tfm::format("Setup next argument source %s, for argument source: %s.", source->getName(), getName());
    if (nextSource_) {
        return nextSource_->setNextSource(source);
    } else {
        nextSource_ = source;
        return this;
    }
}

void ArgumentSource::setupRules(std::shared_ptr<ArgumentRules> argumentRules) {
    DLOG(INFO) << tfm::format("Setup rules for argument sources.");
    for (auto source = this; source != nullptr; source = source->nextSource_.get()) {
        DLOG(INFO) << tfm::format("Setup rules for argument source: %s.", source->getName());
        source->argumentRules_ = argumentRules;
    }
}

std::shared_ptr<const ArgumentRules> ArgumentSource::argumentRules() const {
    return argumentRules_;
}

void ArgumentSource::init(const std::string& usage, const ArgumentSource::UsageOptions& usageOptions) {
    DLOG(INFO) << "Initialize argument sources.";
    std::vector<ArgumentSource*> sources;
    for (auto source = this; source != nullptr; source = source->nextSource_.get()) {
        DLOG(INFO) << tfm::format("Initialize argument source: %s.", source->getName());
        source->doInit(usage, usageOptions);
        sources.push_back(source);
    }
    DLOG(INFO) << "Update rules for argument sources.";
    for (auto source = std::rbegin(sources); source != std::rend(sources); ++source) {
        DLOG(INFO) << tfm::format("Update rules for argument source: %s.", (*source)->getName());
        (*source)->doUpdateRules(argumentRules_);
    }
}

std::string ArgumentSource::readString(const char* argName, ArgumentImportance argImportance) const {
    DLOG(INFO) << tfm::format("Read argument '%s' : %s (%s)", argName, "string", std::to_string(argImportance));
    DLOG(INFO) << tfm::format("ArgumentSource::this = %s", this);
    DLOG(INFO) << tfm::format("Argument Rules: %s", this->argumentRules_.get());
    return ArgumentReadHelper<std::string>(this).read(argName, argImportance);
}

std::vector<std::string> ArgumentSource::readStringList(const char* argName, ArgumentImportance argImportance) const {
    DLOG(INFO) << tfm::format("Read argument '%s' : %s (%s)", argName, "string_list", std::to_string(argImportance));
    return ArgumentReadHelper<std::vector<std::string>>(this).read(argName, argImportance);
}

bool ArgumentSource::readBool(const char* argName, ArgumentImportance argImportance) const {
    DLOG(INFO) << tfm::format("Read argument '%s' : %s (%s)", argName, "boolean", std::to_string(argImportance));
    return ArgumentReadHelper<bool>(this).read(argName, argImportance);
}

int ArgumentSource::readInt(const char* argName, ArgumentImportance argImportance) const {
    DLOG(INFO) << tfm::format("Read argument '%s' : %s (%s)", argName, "integer", std::to_string(argImportance));
    return ArgumentReadHelper<int>(this).read(argName, argImportance);
}

std::string std::to_string(ArgumentImportance argumentImportance) {
    switch (argumentImportance) {
        case ArgumentImportance::Optional:
            return "optional";
        case ArgumentImportance::Required:
            return "required";
    }
}

ArgumentSource::ArgumentSource(ArgumentSource&&) {
    DLOG(INFO) << "Move constructor argument source base.";
}

ArgumentSource& ArgumentSource::operator=(ArgumentSource&&) {
    DLOG(INFO) << "Move assignment argument source base.";
    return *this;
}

ArgumentSource::ArgumentSource() {
    DLOG(INFO) << "Create argument source base.";
}

ArgumentSource::~ArgumentSource() noexcept {
    DLOG(INFO) << "Destroy argument source base.";
}
