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

#include <algorithm>
#include <iostream>
#include <fstream>
#include <iterator>
#include <vector>
#include <stdexcept>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/keys/io/marshaller.h>
#include <virgil/sdk/keys/model/PublicKey.h>
#include <virgil/sdk/keys/http/Connection.h>
#include <virgil/sdk/keys/client/KeysClient.h>

#include <cli/util.h>
#include <cli/config.h>

using virgil::crypto::VirgilByteArray;

using virgil::sdk::keys::io::marshaller;
using virgil::sdk::keys::model::PublicKey;
using virgil::sdk::keys::http::Connection;
using virgil::sdk::keys::client::KeysClient;

PublicKey virgil::cli::get_virgil_public_key(const std::string&  recipientId, const std::string& recipientIdType) {
    // Get owner Virgil Public Key
    KeysClient keysClient(std::make_shared<Connection>(VIRGIL_APP_TOKEN));
    std::vector<PublicKey> publicKeys = keysClient.publicKey().search(recipientId, recipientIdType);
    PublicKey publicKey;
    if (!publicKeys.empty()) {
        publicKey = publicKeys.front();
    }
    return publicKey;
}

PublicKey virgil::cli::read_virgil_public_key(std::istream& file) {
    // Read Virgil Public Key
    std::string publicKeyData((std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>());
    PublicKey publicKey = marshaller<PublicKey>::fromJson(publicKeyData);
    return publicKey;
}

VirgilByteArray virgil::cli::read_bytes(const std::string& in) {
    if(in.empty() || in == "-") {
        return VirgilByteArray((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    }
    std::ifstream inFile(in, std::ios::in | std::ios::binary);
    if (!inFile) {
        throw std::invalid_argument("can not read file: " + in);
    }
    return VirgilByteArray((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
}


void virgil::cli::write_bytes(const std::string& out, const VirgilByteArray& data) {
    if (out.empty()) {
        std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));
        return;
    }

    std::ofstream outFile(out, std::ios::out | std::ios::binary);
    if (!outFile) {
        throw std::invalid_argument("can not write file: " + out);
    }
    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(outFile));
}

void virgil::cli::write_bytes(const std::string& out, const std::string& data) {
    return virgil::cli::write_bytes(out, virgil::crypto::str2bytes(data));
}
