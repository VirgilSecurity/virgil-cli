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

#ifndef VIRGIL_CLI_FILE_DATA_SINK_H
#define VIRGIL_CLI_FILE_DATA_SINK_H

#include <virgil/crypto/VirgilDataSink.h>

#include <functional>
#include <ostream>
#include <memory>

namespace cli { namespace model {

class FileDataSink : public virgil::crypto::VirgilDataSink {
public:
    /**
     * @brief Create sink to the standard output
     */
    FileDataSink();
    /**
     * @brief Create sink to the given file.
     * @param fileName - path to the destination file to be written.
     * @throw ArgumentFileNotFound, if IO errors occurred.
     */
    FileDataSink(const std::string& fileName);

    /**
     * @brief Return true if sink use file for output.
     */
    bool isFileOutput() const;

    /**
     * @brief Return true if sink use console for output.
     */
    bool isConsoleOutput() const;

    /**
     * @brief Add new line to the output.
     */
    void addNewLine();

public:
    virtual bool isGood() override;
    virtual void write(const virgil::crypto::VirgilByteArray& data) override;
    virtual void write(const std::string& text);
private:
    using ostream_deleter = std::function<void(std::ostream*)>;
    using ostream_ptr = std::unique_ptr<std::ostream, ostream_deleter>;
    ostream_ptr out_;
    const bool isFileOutput_;
};

}}

#endif //VIRGIL_CLI_FILE_DATA_SINK_H
