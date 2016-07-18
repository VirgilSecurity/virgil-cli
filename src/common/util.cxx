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

#include <algorithm>
#include <iostream>
#include <fstream>
#include <vector>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilKeyPair.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/pair.h>
#include <cli/version.h>
#include <cli/util.h>
#include <cli/InputShadow.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

vcrypto::VirgilByteArray cli::setPrivateKeyPass(const vcrypto::VirgilByteArray& privateKey) {
    if (vcrypto::VirgilKeyPair::isPrivateKeyEncrypted(privateKey)) {
        std::string privateKeyPass;
        std::cout << "Enter private key password:" << std::endl;
        privateKeyPass = cli::inputShadow();
        vcrypto::VirgilByteArray privateKeyPassByteArray = vcrypto::str2bytes(privateKeyPass);
        if (vcrypto::VirgilKeyPair::checkPrivateKeyPassword(privateKey, privateKeyPassByteArray)) {
            return privateKeyPassByteArray;
        } else {
            throw std::runtime_error("private key pass is invalid");
        }
    }
    return vcrypto::VirgilByteArray();
}

void cli::printVersion(std::ostream& out, const char* programName) {
    out << programName << "  "
        << "version: " << cli::cli_version() << std::endl;
}

void cli::checkFormatRecipientArg(const std::pair<std::string, std::string>& pairRecipientArg) {
    const std::string type = pairRecipientArg.first;
    if (type != "password" && type != "id" && type != "vcard" && type != "email" && type != "pubkey" &&
        type != "private") {
        throw std::invalid_argument("invalid type format: " + type +
                                    ". Expected format: '<key>:<value>'. "
                                    "Where <key> = [password|id|vcard|email|pubkey|private]");
    }
}

void cli::checkFormatIdentity(const std::string& args, const std::string& type) {
    if (type != "email") {
        throw std::invalid_argument(args + " invalid type format: " + type + ". Expected format: '<key>:<value>'. "
                                                                             "Where <key> = [email].");
    }
}

std::string cli::readFile(const std::string& pathnameFile) {
    std::ifstream inFile(pathnameFile, std::ios::in | std::ios::binary);
    if (!inFile) {
        throw std::invalid_argument("can not read file: " + pathnameFile);
    }
    return std::string((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
}

vcrypto::VirgilByteArray cli::readFileBytes(const std::string& in) {
    return vcrypto::str2bytes(cli::readFile(in));
}

std::string cli::readInput(const std::string& in) {
    if (in.empty() || in == "-") {
        return std::string((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    } else {
        std::ifstream inFile(in, std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::invalid_argument("can not read file: " + in);
        }
        return std::string((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    }
}

void cli::writeBytes(const std::string& out, const vcrypto::VirgilByteArray& data) {
    if (out.empty()) {
        std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));
        std::cout << std::endl;
        return;
    }

    std::ofstream outFile(out, std::ios::out | std::ios::binary);
    if (!outFile) {
        throw std::invalid_argument("cannot write file: " + out);
    }
    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(outFile));
}

void cli::writeBytes(const std::string& out, const std::string& data) {
    return cli::writeBytes(out, virgil::crypto::str2bytes(data));
}

void cli::writeOutput(const std::string& out, const std::string& data) {
    if (out.empty()) {
        std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));
        std::cout << std::endl;
        return;
    }

    std::ofstream outFile(out, std::ios::out | std::ios::binary);
    if (!outFile) {
        throw std::invalid_argument("can not write file: " + out);
    }
    outFile << data;
}

std::string cli::getDescriptionMessage(const std::string description, std::vector<std::string> examples) {
    std::string descriptionMessage;
    descriptionMessage += "\nDESCRIPTION:\n" + description;
    if (!examples.empty()) {
        descriptionMessage += "EXAMPLES:\n";
        for (const auto& example : examples) {
            descriptionMessage += example;
        }
    }
    return descriptionMessage;
}
