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

#ifndef VIRGIL_CLI_CONFIG_H
#define VIRGIL_CLI_CONFIG_H

#include <string>

#include <config_path/config_path.h>

#include <virgil/sdk/ServiceUri.h>

#include <cli/consts.h>

#include <iostream>

namespace cli {
struct ConfigFile {
    std::string virgilAccessToken = VIRGIL_ACCESS_TOKEN;
    std::string identityUrl;
    std::string publicKeyUrl;
    std::string privateKeyUrl;

    void setServiceUri(const virgil::sdk::ServiceUri& uri) {
        identityUrl = uri.getIdentityService();
        publicKeyUrl = uri.getPublicKeyService();
        privateKeyUrl = uri.getPrivateKeyService();
    }

    /**
    * @brief Get Service Uri, if identityUrl and publicKeyUrl and privateKeyUrl
    * empty.
    *
    * @return Service Uri
    */
    virgil::sdk::ServiceUri getServiceUri() const {
        const bool isUrls = identityUrl.empty() && publicKeyUrl.empty() && privateKeyUrl.empty();
        return isUrls ? virgil::sdk::ServiceUri() : virgil::sdk::ServiceUri(identityUrl, publicKeyUrl, privateKeyUrl);
    }
};

ConfigFile iniToConfigFile(const std::string& ini);

std::string configFile2ini(const cli::ConfigFile& configFile);

ConfigFile readConfigFile();

ConfigFile readConfigFile(const std::string& path);

void writeConfigFile(const ConfigFile& configFile, const std::string& path);
}

#endif /* VIRGIL_CLI_CONFIG_H */
