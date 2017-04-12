/**
 * Copyright (C) 2015-2017 Virgil Security Inc.
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

#include <cli/model/HashAlgorithm.h>

#include <cli/api/api.h>
#include <cli/error/ArgumentError.h>

using namespace cli;

model::HashAlgorithm model::hash_algorithm_from(const std::string& algorithm) {
    if (algorithm == arg::value::VIRGIL_SIGN_HASH_ALG_SHA1) {
        return model::HashAlgorithm::SHA1;
    } else if (algorithm == arg::value::VIRGIL_SIGN_HASH_ALG_SHA224) {
        return model::HashAlgorithm::SHA224;
    } else if (algorithm == arg::value::VIRGIL_SIGN_HASH_ALG_SHA256) {
        return model::HashAlgorithm::SHA256;
    } else if (algorithm == arg::value::VIRGIL_SIGN_HASH_ALG_SHA384) {
        return model::HashAlgorithm::SHA384;
    } else if (algorithm == arg::value::VIRGIL_SIGN_HASH_ALG_SHA512) {
        return model::HashAlgorithm::SHA512;
    } else {
        throw error::ArgumentValueError(opt::HASH_ALGORITHM, algorithm);
    }
}
