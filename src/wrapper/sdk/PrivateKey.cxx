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

#include <nlohman/json.hpp>

#include <virgil/sdk/io/Marshaller.h>

#include <cli/wrapper/sdk/PrivateKey.h>
#include <cli/util.h>

using json = nlohmann::json;
namespace wsdk = cli::wrapper::sdk;
namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

bool wsdk::isPrivateKeyModel(const std::string& jsonPrivateKeyStr) {
    try {
        json tmp = json::parse(jsonPrivateKeyStr);
        return tmp.is_object() && tmp.find("private_key") != tmp.end() && tmp.find("virgil_card_id") != tmp.end();
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

vsdk::models::PrivateKeyModel wsdk::readPrivateKeyModel(const std::string& inPathnameFile) {
    std::string jPrivateKeyModelStr = cli::readFile(inPathnameFile);
    return vsdk::io::Marshaller<vsdk::models::PrivateKeyModel>::fromJson(jPrivateKeyModelStr);
}

vcrypto::VirgilByteArray wsdk::readPrivateKey(const std::string& inPathnameFile) {
    std::string privateKeyStr = cli::readFile(inPathnameFile);
    vcrypto::VirgilByteArray privateKeyBytes;
    if (wsdk::isPrivateKeyModel(privateKeyStr)) {
        vsdk::models::PrivateKeyModel privateKeyModel =
            vsdk::io::Marshaller<vsdk::models::PrivateKeyModel>::fromJson(privateKeyStr);
        privateKeyBytes = privateKeyModel.getKey();
    } else {
        privateKeyBytes = vcrypto::str2bytes(privateKeyStr);
    }
    return privateKeyBytes;
}

void wsdk::writePrivateKeyModel(const std::string& outPathnameFile,
                                const vsdk::models::PrivateKeyModel& privateKeyModel) {
    std::string jPrivateKeyModelStr = vsdk::io::Marshaller<vsdk::models::PrivateKeyModel>::toJson<4>(privateKeyModel);
    cli::writeOutput(jPrivateKeyModelStr, outPathnameFile);
}
