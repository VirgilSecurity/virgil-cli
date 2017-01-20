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

#ifndef VIRGIL_CLI_CRYPTO_H
#define VIRGIL_CLI_CRYPTO_H

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/VirgilDataSink.h>
#include <virgil/crypto/VirgilDataSource.h>
#include <virgil/crypto/VirgilCipherBase.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/VirgilChunkCipher.h>
#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <cli/model/FileDataSource.h>
#include <cli/model/FileDataSink.h>

#include <memory>
#include <string>

namespace cli {

class Crypto {
public:
    // Basic types
    using Text = std::string;
    using Bytes = virgil::crypto::VirgilByteArray;
    using ByteUtils = virgil::crypto::VirgilByteArrayUtils;
    using KeyPair = virgil::crypto::VirgilKeyPair;
    using KeyAlgorithm = virgil::crypto::VirgilKeyPair::Type;
    using DataSource = virgil::crypto::VirgilDataSource;
    using DataSink = virgil::crypto::VirgilDataSink;
    using CipherBase = virgil::crypto::VirgilCipherBase;
    using StreamCipher = virgil::crypto::VirgilStreamCipher;
    using ChunkCipher = virgil::crypto::VirgilChunkCipher;
    using Hash = virgil::crypto::foundation::VirgilHash;
    using HashAlgorithm = virgil::crypto::foundation::VirgilHash::Algorithm;
    using Base64 = virgil::crypto::foundation::VirgilBase64;
    // Smart pointers
    using DataSourceUnique = std::unique_ptr<DataSource>;
    using DataSinkUnique = std::unique_ptr<DataSink>;
    using CipherBaseUnique = std::unique_ptr<CipherBase>;
    using StreamCipherUnique = std::unique_ptr<StreamCipher>;
    using ChunkCipherUnique = std::unique_ptr<ChunkCipher>;
};

}

#endif //VIRGIL_CLI_CRYPTO_H
