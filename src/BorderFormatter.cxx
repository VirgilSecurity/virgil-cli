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

#include <cli/formatter/BorderFormatter.h>

using cli::formatter::BorderFormatter;

#include <sstream>

static size_t get_multiline_string_length_max(const std::string& str) {
    std::istringstream input(str);
    size_t maxLineLength = 0;
    for (std::string line; std::getline(input, line); maxLineLength = std::max(line.size(), maxLineLength)) {}
    return maxLineLength;
}

static std::string add_horizontal_border(
        const std::string& str, size_t padding, size_t spacing, size_t lineLengthMax,
        char horizontalSymbol, char cornerSymbol) {

    const auto horizontalBorder = std::string(lineLengthMax + padding + spacing, horizontalSymbol);
    std::ostringstream output;
    output << std::endl;
    output << cornerSymbol << horizontalBorder << cornerSymbol << std::endl;
    output << str;
    output << cornerSymbol << horizontalBorder << cornerSymbol << std::endl;
    return output.str();
}

static std::string add_vertical_border(
        const std::string& str, size_t padding, size_t spacing, size_t lineLengthMax, char verticalSymbol) {

    std::istringstream input(str);
    std::ostringstream output;
    const auto paddingString = std::string(padding, ' ');
    for (std::string line; std::getline(input, line);) {
        const auto spacingString = std::string(lineLengthMax - line.length() + spacing, ' ');
        output << verticalSymbol << paddingString << line << spacingString << verticalSymbol << std::endl;
    }

    return output.str();
}

std::string BorderFormatter::format(const std::string& str) const {
    constexpr auto horizontalSymbol = '-';
    constexpr auto verticalSymbol = '|';
    constexpr auto cornerSymbol = '+';
    constexpr size_t padding = 2;
    constexpr size_t spacing = 1;
    const size_t maxLineLength = get_multiline_string_length_max(str);
    return add_horizontal_border(add_vertical_border(str, padding, spacing, maxLineLength, verticalSymbol),
            padding, spacing, maxLineLength, horizontalSymbol, cornerSymbol);
}
