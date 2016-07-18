/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#ifndef VIRGIL_CLI_COMMON_UTIL_H
#define VIRGIL_CLI_COMMON_UTIL_H

#include <string>
#include <vector>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/models/CardModel.h>
#include <virgil/sdk/dto/ValidatedIdentity.h>
#include <virgil/sdk/ServiceUri.h>

#include <cli/ConfigFile.h>

namespace cli {
/**
 * @brief Set private key pass if need. Private key pass asks the user.
 * @param privateKey - user private key
 */
virgil::crypto::VirgilByteArray setPrivateKeyPass(const virgil::crypto::VirgilByteArray& privateKey);

void printVersion(std::ostream& out, const char* programName);

void checkFormatRecipientArg(const std::pair<std::string, std::string>& pairRecipientArg);

void checkFormatIdentity(const std::string& args, const std::string& type);

std::string readFile(const std::string& pathnameFile);

virgil::crypto::VirgilByteArray readFileBytes(const std::string& in);

/**
 * @brief Read bytes from the given source.
 * @param in - if empty or equal to "-" then 'stdin' is used, otherwise - path to file.
 */
std::string readInput(const std::string& in);

/**
 * @brief Write bytes to the given destination.
 * @param out - if empty then 'stdout' ispath to file.
 */
void writeBytes(const std::string& out, const virgil::crypto::VirgilByteArray& data);
void writeBytes(const std::string& out, const std::string& data);

void writeOutput(const std::string& out, const std::string& data);

std::string getDescriptionMessage(const std::string description, std::vector<std::string> examples);
}

#endif /* VIRGIL_CLI_COMMON_UTIL_H */
