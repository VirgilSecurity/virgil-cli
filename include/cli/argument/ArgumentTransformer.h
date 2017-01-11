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

#ifndef VIRGIL_CLI_VALUE_READER_H
#define VIRGIL_CLI_VALUE_READER_H

#include <cli/crypto/Crypto.h>

#include <virgil/sdk/client/Client.h>

#include <string>
#include <vector>
#include <type_traits>

namespace cli {
namespace command {
class Command;
}
namespace model {
class Recipient;
class SecureKey;
}
}

namespace cli { namespace argument {

class OneArgumentTransformer {
public:
    explicit OneArgumentTransformer(std::string argumentValue)
            : argumentValue_(std::move(argumentValue)) { }

    virtual ~OneArgumentTransformer() noexcept = default;
protected:
    std::string argumentValue_;
};

class ListArgumentTransformer {
public:
    ListArgumentTransformer(const std::vector<std::string>& argumentValueList)
            : argumentValueList_(argumentValueList) { }
protected:
    std::vector<std::string> argumentValueList_;

};

template <typename T>
class ArgumentTransformer : public OneArgumentTransformer {
public:
    using OneArgumentTransformer::OneArgumentTransformer;
};

// Specialization for Crypto::Text
template<>
class ArgumentTransformer<cli::Crypto::Text> : public OneArgumentTransformer {
public:
    using OneArgumentTransformer::OneArgumentTransformer;
    Crypto::Text toText() const;
    Crypto::Bytes toBytes() const;
};

// Specialization for Crypto::KeyAlgorithm
template<>
class ArgumentTransformer<cli::Crypto::KeyAlgorithm> : public OneArgumentTransformer {
public:
    using OneArgumentTransformer::OneArgumentTransformer;
    Crypto::KeyAlgorithm transform() const;
};

// Specialization for command::Command
template<>
class ArgumentTransformer<cli::command::Command> : public OneArgumentTransformer {
public:
    using OneArgumentTransformer::OneArgumentTransformer;
    std::unique_ptr<cli::command::Command> transform() const;
};

// Specialization for Crypto::FileDataSink
template<>
class ArgumentTransformer<Crypto::FileDataSource> : public OneArgumentTransformer {
public:
    using OneArgumentTransformer::OneArgumentTransformer;
    std::unique_ptr<cli::Crypto::FileDataSource> transform() const;
};

// Specialization for Crypto::FileDataSink
template<>
class ArgumentTransformer<cli::Crypto::FileDataSink> : public OneArgumentTransformer {
public:
    using OneArgumentTransformer::OneArgumentTransformer;
    std::unique_ptr<cli::Crypto::FileDataSink> transform() const;
};

// Specialization for model::Recipient
template<>
class ArgumentTransformer<model::Recipient> : public ListArgumentTransformer {
public:
    using ListArgumentTransformer::ListArgumentTransformer;
    std::vector<std::unique_ptr<model::Recipient>> transform() const;
};

// Specialization for model::SecureKey
template<>
class ArgumentTransformer<model::SecureKey> : public OneArgumentTransformer {
public:
    using OneArgumentTransformer::OneArgumentTransformer;
    std::unique_ptr<model::SecureKey> transform() const;
};

// Specialization for virgil::sdk::client::Client
template<>
class ArgumentTransformer<virgil::sdk::client::Client> : public OneArgumentTransformer {
public:
    using OneArgumentTransformer::OneArgumentTransformer;
    std::unique_ptr<virgil::sdk::client::Client> transform() const;
};

// Helpers
template<typename T>
using ArgumentTransformerPtr = std::unique_ptr<ArgumentTransformer<T>>;

template<typename T, typename V>
inline ArgumentTransformerPtr<T> make_transformer(const V& value) {
    return std::make_unique<ArgumentTransformer<T>>(value);
};

}}

#endif //VIRGIL_CLI_VALUE_READER_H
