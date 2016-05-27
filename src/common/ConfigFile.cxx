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

#if defined(WIN32)
#include <config_path.h>
#include <Windows.h>
#endif

#include <cli/ConfigFile.h>

namespace vsdk = virgil::sdk;

static virgil::cli::ConfigFile iniToConfigFile(const std::string& ini) {
    try {
        std::stringstream ss(ini);
        INI::Parser iniParser(ss);

        virgil::cli::ConfigFile configFile;
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

static virgil::cli::ConfigFile readGlobalConfigFile(const std::string& pathGlobalConfigFile, const bool verbose) {
    std::ifstream inGlobalConfigFile(pathGlobalConfigFile, std::ios::in | std::ios::binary);
    if (!inGlobalConfigFile) {
        virgil::cli::ConfigFile defaultConfigFile;
        if (verbose) {
            std::cout << "Can't read global config file by path:" << pathGlobalConfigFile << std::endl;
            std::cout << "Set default values." << std::endl;
        }

        return defaultConfigFile;
    }

    std::string ini((std::istreambuf_iterator<char>(inGlobalConfigFile)), std::istreambuf_iterator<char>());
    return iniToConfigFile(ini);
}

virgil::cli::ConfigFile virgil::cli::readConfigFile(const bool verbose) {
    std::string pathGlobalConfigFile;
    std::string pathLocalConfigFile;

#if defined(WIN32)
    pathGlobalConfigFile = get_all_user_config_folder("virgil-cli");
    pathGlobalConfigFile += "\\virgil-cli.ini";

    pathLocalConfigFile = get_user_config_folder("virgil-cli");
    pathLocalConfigFile += "\\virgil-cli.ini";
#else
    pathGlobalConfigFile = INSTALL_CONFIG_FILE_GLOBAL_DIR + "/virgil-cli.conf";
    pathLocalConfigFile = INSTALL_CONFIG_FILE_LOCAL_DIR + "/virgil-cli.conf";
#endif

    if (verbose) {
        std::cout << "pathGlobalConfigFile = " << pathGlobalConfigFile << std::endl;
        std::cout << "pathLocalConfigFile = " << pathLocalConfigFile << std::endl;
        std::cout << std::endl;
    }

    virgil::cli::ConfigFile globalConfigFile = readGlobalConfigFile(pathGlobalConfigFile, verbose);

    std::ifstream inLocalConfigFile(pathLocalConfigFile, std::ios::in | std::ios::binary);
    if (!inLocalConfigFile) {
        if (verbose) {
            std::cout << "Can't read local config file by path:" << pathLocalConfigFile << std::endl;
            std::cout << "Set values from global config." << std::endl;
        }

        return globalConfigFile;
    }

    std::string ini((std::istreambuf_iterator<char>(inLocalConfigFile)), std::istreambuf_iterator<char>());
    virgil::cli::ConfigFile localConfigFile = iniToConfigFile(ini);

    std::string identityServiceUri;
    std::string publicServiceUri;
    std::string privateServiceUri;
    if (localConfigFile.virgilAccessToken.empty()) {
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
