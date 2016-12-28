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

#include <cli/api/utils.h>

#include <cli/api/api.h>
#include <cli/error/ArgumentError.h>
#include <cli/argument/ArgumentSource.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>

using namespace cli;

using Bytes = virgil::crypto::VirgilByteArray;
using ByteUtils = virgil::crypto::VirgilByteArrayUtils;
using KeyType = virgil::crypto::VirgilKeyPair::Type;


template <>
Bytes api::get<Bytes>::from(const std::string& from) {
    return ByteUtils::stringToBytes(from);
}

template <>
KeyType api::get<KeyType>::from(const std::string& from) {
    if (from == arg::value::VIRGIL_KEYGEN_ALG_BP256R1) {
        return KeyType::EC_BP256R1;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_BP384R1) {
        return KeyType::EC_BP384R1;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_BP512R1) {
        return KeyType::EC_BP512R1;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_ED25519) {
        return KeyType::FAST_EC_ED25519;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_RSA3072) {
        return KeyType::RSA_3072;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_RSA4096) {
        return KeyType::RSA_4096;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_RSA8192) {
        return KeyType::RSA_8192;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_SECP192K1) {
        return KeyType::EC_SECP192K1;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_SECP192R1) {
        return KeyType::EC_SECP192R1;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_SECP224K1) {
        return KeyType::EC_SECP224K1;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_SECP224R1) {
        return KeyType::EC_SECP224R1;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_SECP256K1) {
        return KeyType::EC_SECP256K1;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_SECP256R1) {
        return KeyType::EC_SECP256R1;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_SECP384R1) {
        return KeyType::EC_SECP384R1;
    } else if (from == arg::value::VIRGIL_KEYGEN_ALG_SECP521R1) {
        return KeyType::EC_SECP521R1;
    } else {
        throw error::ArgumentValueError(opt::ALGORITHM, from);
    }
}
