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
 *     (3) Neither the name of the copyright holder nor the names of itsk
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

#include <fstream>
#include <stdexcept>
#include <iterator>

#include <virgil/sdk/io/Marshaller.h>

#include <cli/wrapper/sdk/CardClient.h>
#include <cli/ConfigFile.h>

namespace vsdk = virgil::sdk;
namespace wsdk = virgil_cli::wrapper::sdk;
namespace vcli = virgil::cli;

wsdk::CardClient::CardClient() : servicesHub_(initFromConfigFile()) {
}

wsdk::CardClient::CardClient(const virgil::sdk::ServicesHub& servicesHub) : servicesHub_(servicesHub) {
}

vsdk::models::CardModel wsdk::CardClient::getCardById(const std::string& recipientId) {
    return servicesHub_.card().get(recipientId);
}

std::vector<vsdk::models::CardModel> wsdk::CardClient::getGlobalCards(const std::string& email) {
    return servicesHub_.card().searchGlobal(email, vsdk::dto::IdentityType::Email);
}

std::vector<vsdk::models::CardModel> wsdk::CardClient::getConfirmedPrivateCards(const std::string& value,
                                                                                const std::string& type) {
    return servicesHub_.card().search(value, type);
}

vsdk::ServicesHub wsdk::CardClient::initFromConfigFile() {
    vcli::ConfigFile configFile = vcli::readConfigFile();
    return vsdk::ServicesHub(configFile.virgilAccessToken, configFile.serviceUri);
}

virgil::sdk::models::CardModel wsdk::readCard(const std::string& in) {
    std::ifstream inFile(in, std::ios::in | std::ios::binary);
    if (!inFile) {
        throw std::invalid_argument("can't read file by path: " + in);
    }
    std::string jsonCard((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    return vsdk::io::Marshaller<vsdk::models::CardModel>::fromJson(jsonCard);
}
