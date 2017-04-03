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

#include <cli/model/FileDataSink.h>

#include <cli/crypto/Crypto.h>
#include <cli/error/ArgumentError.h>

#include <iostream>
#include <fstream>

using cli::model::FileDataSink;

FileDataSink::FileDataSink() : out_(ostream_ptr(&std::cout, [](std::ostream*) {})), isFileOutput_(false) {
}

FileDataSink::FileDataSink(const std::string& fileName)
        : out_(ostream_ptr(new std::ofstream(fileName), std::default_delete<std::ostream>())), isFileOutput_(true) {
    if (!*out_) {
        throw error::ArgumentFileNotFound(fileName);
    }
}

bool FileDataSink::isFileOutput() const {
    return isFileOutput_;
}

bool FileDataSink::isConsoleOutput() const {
    return !isFileOutput_;
}

void FileDataSink::addNewLine() {
    *out_ << std::endl;
}

bool FileDataSink::isGood() {
    return out_->good();
}

void FileDataSink::write(const virgil::crypto::VirgilByteArray& data) {
    out_->write(reinterpret_cast<const std::ostream::char_type*>(data.data()), data.size());
}

void FileDataSink::write(const std::string& text) {
    out_->write(reinterpret_cast<const std::ostream::char_type*>(text.data()), text.size());
}
