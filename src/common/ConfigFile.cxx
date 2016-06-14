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
#include <sstream>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include <cli/ini.hpp>
#include <cli/ConfigFile.h>

namespace vcli = virgil::cli;
namespace vsdk = virgil::sdk;

static vcli::ConfigFile iniToConfigFile(const std::string& ini) {
    try {
        std::stringstream ss(ini);
        INI::Parser iniParser(ss);

        vcli::ConfigFile configFile;
        configFile.virgilAccessToken = iniParser.top()("Virgil Access Token")["token"];
        configFile.serviceUri =
            vsdk::ServiceUri(iniParser.top()("URI")["identity-service"], iniParser.top()("URI")["public-key-service"],
                             iniParser.top()("URI")["private-key-service"]);
        return configFile;

    } catch (std::runtime_error& exception) {
        std::string error = "Can't parse config file: " + ini + "\n";
        error += exception.what();
        throw std::runtime_error(error);
    }
}

static vcli::ConfigFile readGlobalConfigFile(const std::string& pathGlobalConfigFile, const bool verbose) {
    std::ifstream inGlobalConfigFile(pathGlobalConfigFile, std::ios::in | std::ios::binary);
    if (!inGlobalConfigFile) {
        vcli::ConfigFile defaultConfigFile;
        if (verbose) {
            std::cout << "Can't read global config file by path:" << pathGlobalConfigFile << std::endl;
            std::cout << "Set default values." << std::endl;
        }
        return defaultConfigFile;
    }

    std::string ini((std::istreambuf_iterator<char>(inGlobalConfigFile)), std::istreambuf_iterator<char>());
    return iniToConfigFile(ini);
}

vcli::ConfigFile vcli::readConfigFile(const bool verbose) {
    std::string configFileName;
#if defined(WIN32)
    configFileName = "\\virgil-cli.ini";
#else
    configFileName = "/virgil-cli.conf";
#endif

    std::string pathGlobalConfigFile = get_all_user_config_folder("virgil-cli") + configFileName;
    std::string pathLocalConfigFile = get_user_config_folder("virgil-cli") + configFileName;

    vcli::ConfigFile globalConfigFile = readGlobalConfigFile(pathGlobalConfigFile, verbose);

    std::ifstream inLocalConfigFile(pathLocalConfigFile, std::ios::in | std::ios::binary);
    if (!inLocalConfigFile) {
        if (verbose) {
            std::cout << "Can't read local config file by path:" << pathLocalConfigFile << std::endl;
            std::cout << "Set values from global config." << std::endl;
        }

        if (globalConfigFile.virgilAccessToken == "@" || globalConfigFile.virgilAccessToken.empty()) {
            throw std::runtime_error("The Virgil Access Token was not set. "
                                     "That set Virgil Access Token see 'virgil config'.");
        }

        return globalConfigFile;
    }

    std::string ini((std::istreambuf_iterator<char>(inLocalConfigFile)), std::istreambuf_iterator<char>());
    vcli::ConfigFile localConfigFile = iniToConfigFile(ini);

    std::string identityServiceUri;
    std::string publicServiceUri;
    std::string privateServiceUri;
    if (localConfigFile.virgilAccessToken.empty()) {
        if (globalConfigFile.virgilAccessToken == "@" || globalConfigFile.virgilAccessToken.empty()) {
            throw std::runtime_error("Don't set Virgil Access Token."
                                     "That set Virgil Access Token see 'virgil config'.");
        }

        localConfigFile.virgilAccessToken = globalConfigFile.virgilAccessToken;
    } else {
        identityServiceUri = localConfigFile.virgilAccessToken;
    }

    if (localConfigFile.serviceUri.getIdentityService().empty()) {
        identityServiceUri = globalConfigFile.serviceUri.getIdentityService();
    } else {
        identityServiceUri = localConfigFile.serviceUri.getIdentityService();
    }

    if (localConfigFile.serviceUri.getPublicKeyService().empty()) {
        publicServiceUri = globalConfigFile.serviceUri.getPublicKeyService();
    } else {
        publicServiceUri = localConfigFile.serviceUri.getPublicKeyService();
    }

    if (localConfigFile.serviceUri.getPrivateKeyService().empty()) {
        privateServiceUri = globalConfigFile.serviceUri.getPrivateKeyService();
    } else {
        privateServiceUri = localConfigFile.serviceUri.getPrivateKeyService();
    }

    localConfigFile.serviceUri = virgil::sdk::ServiceUri(identityServiceUri, publicServiceUri, privateServiceUri);

    if (verbose) {
        std::cout << "[Virgil Access Token]" << std::endl;
        std::cout << localConfigFile.virgilAccessToken << "\n\n";

        std::cout << "[URI]" << std::endl;
        std::cout << "identity-service:" << std::endl;
        std::cout << localConfigFile.serviceUri.getIdentityService() << "\n\n";

        std::cout << "public-key-service:" << std::endl;
        std::cout << localConfigFile.serviceUri.getPublicKeyService() << "\n\n";

        std::cout << "private-key-service:" << std::endl;
        std::cout << localConfigFile.serviceUri.getPrivateKeyService() << "\n\n";
    }
    return localConfigFile;
}
