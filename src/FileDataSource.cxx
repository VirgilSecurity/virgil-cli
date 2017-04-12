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

#include <cli/model/FileDataSource.h>

#include <cli/crypto/Crypto.h>
#include <cli/error/ArgumentError.h>

#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>

using cli::Crypto;
using cli::model::FileDataSource;

FileDataSource::FileDataSource(size_t chunkSize) : in_(&std::cin, [](std::istream*){}), chunkSize_(chunkSize) {
}

FileDataSource::FileDataSource(const std::string& fileName, size_t chunkSize)
        : in_(new std::ifstream(fileName), std::default_delete<std::istream>()), chunkSize_(chunkSize) {
    if (!*in_) {
        throw error::ArgumentFileNotFound(fileName);
    }
}

bool FileDataSource::hasData() {
    return in_->good();
}

Crypto::Bytes FileDataSource::read() {
    Crypto::Bytes result(chunkSize_);
    in_->read(reinterpret_cast<std::istream::char_type*>(result.data()), result.size());
    if (!*in_) {
        // Only part of chunk was read, so result MUST be trimmed.
        result.resize(static_cast<size_t>(in_->gcount()));
    }
    return result;
}

Crypto::Bytes FileDataSource::readAll() {
    Crypto::Bytes result;
    std::copy(std::istreambuf_iterator<char>(*in_), std::istreambuf_iterator<char>(), std::back_inserter(result));
    return result;
}

Crypto::Text FileDataSource::readLine() {
    Crypto::Text result;
    std::getline(*in_, result);
    return result;
}

std::vector<Crypto::Text> FileDataSource::readMultiLine() {
    std::vector<Crypto::Text> result;
    for (Crypto::Text line; std::getline(*in_, line); result.push_back(std::move(line)));
    return result;
}

Crypto::Text FileDataSource::readText() {
    Crypto::Text result;
    std::copy(std::istreambuf_iterator<char>(*in_), std::istreambuf_iterator<char>(), std::back_inserter(result));
    return result;
}
