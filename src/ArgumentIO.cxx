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

#include <cli/argument/ArgumentIO.h>

#include <cli/api/api.h>
#include <cli/api/utils.h>

#include <cli/logger/Logger.h>

#include <istream>
#include <ostream>
#include <fstream>
#include <iostream>

using cli::argument::ArgumentIO;
using cli::argument::ArgumentSource;

static void write_file_bytes(const std::string& fileName, const ArgumentIO::Bytes& bytes) {
    if (!fileName.empty()) {
        ULOG(1, INFO) << tfm::format("Write output to the file '%s'.", fileName);
        std::ofstream file(fileName);
        std::copy(std::begin(bytes), std::end(bytes), std::ostreambuf_iterator<char>(file));
    } else {
        ULOG(1, INFO) << "Write output to the standard output.";
        std::copy(std::begin(bytes), std::end(bytes), std::ostreambuf_iterator<char>(std::cout));
    }
}

static ArgumentIO::Bytes read_file_bytes(const std::string& fileName) {
    ArgumentIO::Bytes bytes;
    if (!fileName.empty()) {
        ULOG(1, INFO) << tfm::format("Read from file %s.", fileName);
        std::ifstream file(fileName);
        std::copy(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>(),
                std::back_inserter(bytes));
    } else {
        ULOG(1, INFO) << "Read file from the standard input.";
        std::copy(std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>(),
                std::back_inserter(bytes));
    }
    return bytes;
}

std::string ArgumentIO::readCommand(const std::unique_ptr<ArgumentSource>& argumentSource) const {
    return argumentSource->readString(arg::COMMAND, ArgumentImportance::Required);
}

ArgumentIO::KeyAlgorithm ArgumentIO::readKeyAlgorithm(const std::unique_ptr<ArgumentSource>& argumentSource) const {
    return api::get<ArgumentIO::KeyAlgorithm>::from(
            argumentSource->readString(opt::ALGORITHM, ArgumentImportance::Optional));
}

ArgumentIO::Bytes ArgumentIO::readInput(const std::unique_ptr<ArgumentSource>& argumentSource) const {
    return read_file_bytes(argumentSource->readString(opt::IN, ArgumentImportance::Optional));
}

ArgumentIO::Bytes ArgumentIO::readKeyPassword(const std::unique_ptr<ArgumentSource>& argumentSource) const {
    auto noPassword = argumentSource->readBool(opt::NO_PASSWORD, ArgumentImportance::Optional);
    if (noPassword) {
        return Bytes();
    }
    auto keyPassword =
            argumentSource->readString(opt::PRIVATE_KEY_PASSWORD, ArgumentImportance::Required);
    return api::get<ArgumentIO::Bytes>::from(keyPassword);
}

void ArgumentIO::writeOutput(const std::unique_ptr<ArgumentSource>& argumentSource, const Bytes& bytes) const {
    write_file_bytes(argumentSource->readString(opt::OUT, ArgumentImportance::Optional), bytes);
}
