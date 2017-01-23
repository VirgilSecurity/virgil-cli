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
#include <cli/io/Logger.h>

#undef IN
#undef OUT

using cli::argument::Argument;
using cli::argument::ArgumentSource;
using cli::argument::ArgumentRules;
using cli::argument::ArgumentImportance;


namespace cli { namespace argument { namespace internal {

static std::string to_string(const std::vector<const char *> argNames) {
    std::string result = "{";
    for (auto item : argNames) {
        if (item != argNames[0]) {
            result += ", ";
        }
        result += *item;
    }
    result += "}";
    return result;
}

}}}

const char* ArgumentSource::getName() const {
    return doGetName();
}

ArgumentSource* ArgumentSource::appendSource(std::unique_ptr<ArgumentSource> source) {
    if (nextSource_) {
        return nextSource_->appendSource(std::move(source));
    } else {
        LOG(INFO) << tfm::format("Append argument source: %s->%s.", getName(), source->getName());
        nextSource_ = std::move(source);
        return this;
    }
}

void ArgumentSource::setupRules(std::shared_ptr<ArgumentRules> argumentRules) {
    LOG(INFO) << tfm::format("Setup rules for argument sources.");
    for (auto source = this; source != nullptr; source = source->nextSource_.get()) {
        LOG(INFO) << tfm::format("Setup rules for argument source: %s.", source->getName());
        source->argumentRules_ = argumentRules;
    }
}

std::shared_ptr<ArgumentRules> ArgumentSource::getArgumentRules() {
    DCHECK(argumentRules_ != nullptr);
    return argumentRules_;
}

std::shared_ptr<const ArgumentRules> ArgumentSource::getArgumentRules() const {
    DCHECK(argumentRules_ != nullptr);
    return argumentRules_;
}

void ArgumentSource::init(const std::string& usage, const ArgumentParseOptions& parseOptions) {
    LOG(INFO) << "Initialize argument sources.";
    std::vector<ArgumentSource*> sources;
    for (auto source = this; source != nullptr; source = source->nextSource_.get()) {
        LOG(INFO) << tfm::format("Initialize argument source: %s.", source->getName());
        source->doInit(usage, parseOptions);
        sources.push_back(source);
    }
    LOG(INFO) << "Update rules for argument sources.";
    for (auto source = sources.rbegin(); source != sources.rend(); ++source) {
        LOG(INFO) << tfm::format("Update rules for argument source: %s.", (*source)->getName());
        (*source)->doUpdateRules();
    }
}

Argument ArgumentSource::read(const char* argName, ArgumentImportance argImportance) const {
    LOG(INFO) << tfm::format("Search source for argument: '%s' (%s)", argName, std::to_string(argImportance));
    for (auto source = this; source != nullptr; source = source->nextSource_.get()) {
        LOG(INFO) << "Ask source:" << source->getName();
        if (source->doCanRead(argName, argImportance)) {
            LOG(INFO) << tfm::format("Read argument: '%s' (%s), from the source: %s.",
                    argName, std::to_string(argImportance), source->getName());
            return source->doRead(argName);
        }
    }
    switch (argImportance) {
        case ArgumentImportance::Required:
            LOG(ERROR) << tfm::format("Required argument '%s' is not defined.", argName);
            throw error::ArgumentNotFoundError(argName);
        case ArgumentImportance::Optional:
            LOG(WARNING) << tfm::format("Optional argument '%s' is not defined. Return empty value.", argName);
            return Argument();
    }
}

Argument ArgumentSource::read(const std::vector<const char*>& argNames, ArgumentImportance argImportance) const {
    const auto argNamesString = internal::to_string(argNames);
    LOG(INFO) << tfm::format("Search source for arguments: '%s' (%s)", argNamesString, std::to_string(argImportance));
    for (auto argName : argNames) {
        LOG(INFO) << tfm::format("Try find source for argument: '%s'", argName);
        for (auto source = this; source != nullptr; source = source->nextSource_.get()) {
            LOG(INFO) << "Ask source:" << source->getName();
            if (source->doCanRead(argName, ArgumentImportance::Optional)) { // Optional, because of "OR" read
                LOG(INFO) << tfm::format("Read argument: '%s' (%s), from the source: %s.",
                        argName, std::to_string(argImportance), source->getName());
                return source->doRead(argName);
            }
        }
    }
    switch (argImportance) {
        case ArgumentImportance::Required:
            LOG(ERROR) << tfm::format("Required argument '%s' is not defined.", argNamesString);
            throw error::ArgumentNotFoundError(argNamesString);
        case ArgumentImportance::Optional:
            LOG(WARNING) << tfm::format("Optional argument '%s' is not defined. Return empty value.", argNamesString);
            return Argument();
    }
}
