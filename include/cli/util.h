/**
 * Copyright (C) 2015 Virgil Security Inc.
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

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/keys/model/PublicKey.h>

#include <virgil/sdk/privatekeys/model/ContainerType.h>
#include <virgil/sdk/privatekeys/model/UserData.h>

namespace virgil { namespace cli {

/**
 * @brief Retive Virgil Public Key from the Virgil Public Key service.
 */
virgil::sdk::keys::model::PublicKey get_virgil_public_key(const std::string& userId);

/**
 * @brief Read Virgil Public Key from the file.
 */
virgil::sdk::keys::model::PublicKey read_virgil_public_key(std::istream& file);

/**
 * @brief Read bytes from the given source.
 * @param in - if empty or equal to "-" then 'stdin' is used, otherwise - path to file.
 */
virgil::crypto::VirgilByteArray read_bytes(const std::string& in);

/**
 * @brief Write bytes to the given destination.
 * @param out - if empty or equal to "-" then 'stdout' is used, otherwise - path to file.
 */
void write_bytes(const std::string& out, const virgil::crypto::VirgilByteArray& data);
void write_bytes(const std::string& out, const std::string& data);

void print_version(std::ostream& out, const char *programName);



void checkFormatUserId(const std::pair<std::string, std::string>& pair);

void checkFormatPublicId(const std::pair<std::string, std::string>& pair);


virgil::sdk::privatekeys::model::UserData getUserData(const std::string& type, const std::string& value);

std::string getPublicKeyId(const std::string& type, const std::string& value);

virgil::sdk::privatekeys::model::ContainerType fromString(const std::string& type);

}}

#endif /* VIRGIL_CLI_COMMON_UTIL_H */
