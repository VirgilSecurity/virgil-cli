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

#include <cli/cmd/CommandPrompt.h>

#include <tinyformat/tinyformat.h>

using cli::cmd::CommandPrompt;

static constexpr const char kPromtString[] = ">>> ";

void CommandPrompt::init(const std::string& usage) {
    doInit(usage);
}

std::string CommandPrompt::readString(const char *argName) const {
    auto message = getPromptMessage(argName);
    doWriteNewLine(message);
    std::string result;
    do {
        doWrite(kPromtString);
        result = doRead();
    } while (!checkResult(argName, result));
    return result;
}

std::string CommandPrompt::readSecureString(const char* argName) const {
    auto message = getPromptMessage(argName);
    doWriteNewLine(message);
    std::string result;
    do {
        doWrite(kPromtString);
        result = doSecureRead();
    } while (!checkResult(argName, result));
    return result;
}

std::vector<std::string> CommandPrompt::readStringList(const char* argName) const {
    auto message = getPromptMessage(argName);
    doWriteNewLine(message);
    std::vector<std::string> result;
    do {
        doWrite(kPromtString);
        std::string value;
        bool isValueValid;
        do {
            value = doRead();
            isValueValid = checkResult(argName, value);
            if (checkResult(argName, value)) {
                result.push_back(std::move(value));
            }
        } while (isValueValid);
    } while (!checkResult(argName, result));
    return result;
}

bool CommandPrompt::readBool(const char *argName) const {
    auto message = getPromptMessage(argName);
    doWriteNewLine(message);
    std::string result;
    do {
        doWrite(kPromtString);
        result = doRead();
    } while (!checkResult(argName, result));
    return result == "YES" || result == "yes";
}

int CommandPrompt::readInt(const char *argName) const {
    auto message = getPromptMessage(argName);
    doWriteNewLine(message);
    std::string result;
    do {
        doWrite(kPromtString);
        result = doRead();
    } while (!checkResult(argName, result));
    return 0;
}

std::string CommandPrompt::getPromptMessage(const char* argName) const {
    return tfm::format("Type value for option: %s", argName);
}

bool CommandPrompt::checkResult(const char* argName, const std::string& result) const {
    return !result.empty();
}

bool CommandPrompt::checkResult(const char* argName, const std::vector<std::string>& result) const {
    return !result.empty();
}
