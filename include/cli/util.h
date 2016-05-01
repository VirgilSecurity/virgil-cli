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
#include <vector>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/models/CardModel.h>
#include <virgil/sdk/dto/ValidatedIdentity.h>
#include <virgil/sdk/ServiceUri.h>

#include <cli/config.h>

namespace virgil {
namespace cli {

    struct ConfigFile {
        std::string virgilAccessToken = VIRGIL_ACCESS_TOKEN;
        virgil::sdk::ServiceUri serviceUri = virgil::sdk::ServiceUri();
    };


    ConfigFile readConfigFile(const bool verbose);

    std::string inputShadow();

    /**
     * @brief Set private key pass if need. Private key pass asks the user.
     * @param privateKey - user private key
     */
    virgil::crypto::VirgilByteArray setPrivateKeyPass(const virgil::crypto::VirgilByteArray& privateKey);

    bool isPublicKeyModel(const std::string& publicKey);

    bool isPrivateKeyModel(const std::string& privateKey);

    //-------------------------------------------------------------------------------------

    void printVersion(std::ostream& out, const char* programName);

    //-------------------------------------------------------------------------------------

    void checkFormatRecipientArg(const std::pair<std::string, std::string>& pairRecipientArg);

    void checkFormatIdentity(const std::string& args, const std::string& type);

    //-------------------------------------------------------------------------------------

    virgil::crypto::VirgilByteArray readFileBytes(const std::string& in);

    /**
     * @brief Read bytes from the given source.
     * @param in - if empty or equal to "-" then 'stdin' is used, otherwise - path to file.
     */
    std::string readInput(const std::string& in);

    virgil::sdk::dto::ValidatedIdentity readValidateIdentity(const std::string& in);

    virgil::sdk::models::CardModel readCard(const std::string& in);

    /**
     * @brief Read public key from the public key model or public key byte array source
     * @param in - path to file.
     */
    virgil::crypto::VirgilByteArray readPublicKey(const std::string& in);

    /**
     * @brief Read private key from the private key model or private key byte array source
     * @param in - path to file.
     */
    virgil::crypto::VirgilByteArray readPrivateKey(const std::string& in);

    //-------------------------------------------------------------------------------------

    /**
     * @brief Write bytes to the given destination.
     * @param out - if empty or equal to "-" then 'stdout' is used, otherwise - path to file.
     */
    void writeBytes(const std::string& out, const virgil::crypto::VirgilByteArray& data);
    void writeBytes(const std::string& out, const std::string& data);

    std::string getDescriptionMessage(const std::string description, std::vector<std::string> examples);

    //-------------------------------------------------------------------------------------

    std::vector<virgil::sdk::models::CardModel> getRecipientCards(const std::string& type, const std::string& value,
                                                                  const bool includeUnconrimedCard);

    std::vector<std::string> getRecipientCardsId(const std::string& type, const std::string& value,
                                                 const bool includeUnconrimedCard);
}
}

#endif /* VIRGIL_CLI_COMMON_UTIL_H */
