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

#include <cli/formatter/KeyValueFormatter.h>

#include <cli/io/Logger.h>

#include <algorithm>
#include <sstream>

using cli::formatter::KeyValueFormatter;

static inline std::string& rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}
static std::string find_and_replace(const std::string& source, std::string const& find, std::string const& replace) {
    std::string result = source;
    for(std::string::size_type pos = 0; (pos = result.find(find, pos)) != std::string::npos;) {
        result.replace(pos, find.length(), replace);
        pos += replace.length();
    }
    return rtrim(result);
}

static std::string wrap_multiline(const std::string& lines, size_t padding) {
    const std::string from = "\n";
    const std::string to = from + std::string(padding, ' ');
    return find_and_replace(lines, from, to);
}

KeyValueFormatter::KeyValueFormatter(size_t width) : width_(width) {
    DCHECK(width_ > 0);
}

std::string KeyValueFormatter::format(const Container& container) const {
    size_t maxKeyLength = 0;
    for (const auto& keyValue: container) {
        maxKeyLength = std::max(keyValue.first.size(), maxKeyLength);
    }

    std::ostringstream out;
    for (const auto& keyValue: container) {
        const auto& key = keyValue.first;
        const auto& value = keyValue.second;
        const auto keyPadding = maxKeyLength - key.size();
        const auto paddingSymbol = ' ';
        const std::string separationSymbol = " : ";
        out << key << std::string(keyPadding, paddingSymbol) << separationSymbol;
        out << wrap_multiline(value, maxKeyLength + separationSymbol.size()) << "\n";
    }
    return out.str();
}
