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
#include <cfgpath.h>
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
        return virgil::cli::ConfigFile();
    }

    std::string ini((std::istreambuf_iterator<char>(inGlobalConfigFile)), std::istreambuf_iterator<char>());
    return iniToConfigFile(ini);
}

virgil::cli::ConfigFile virgil::cli::readConfigFile(const bool verbose) {
    std::string pathGlobalConfigFile;
    std::string pathLocalConfigFile;

#if defined(WIN32)
    char cfgdir[MAX_PATH];
    get_user_config_folder(cfgdir, sizeof(cfgdir), "virgil-cli");
    if (cfgdir[0] == 0) {
        if (verbose) {
            std::cout << "Can't find config file";
        }
        return ConfigFile();
    } else {
        if (verbose) {
            std::cout << "File found by path:" << std::string(cfgdir) << std::endl;
        }
    }

    pathLocalConfigFile = std::string(cfgdir);
    pathLocalConfigFile += "\\virgil-cli.ini";
#else
    pathGlobalConfigFile = INSTALL_CONFIG_FILE_GLOBAL_DIR + "/virgil-cli.conf";
    pathLocalConfigFile = INSTALL_CONFIG_FILE_LOCALE_DIR + "/virgil-cli.conf";
#endif

    virgil::cli::ConfigFile globalConfigFile = readGlobalConfigFile(pathGlobalConfigFile, verbose);
    std::ifstream inLocalConfigFile(pathLocalConfigFile, std::ios::in | std::ios::binary);
    if (!inLocalConfigFile) {
        return globalConfigFile;
    }

    std::string ini((std::istreambuf_iterator<char>(inLocalConfigFile)), std::istreambuf_iterator<char>());
    virgil::cli::ConfigFile localConfigFile = iniToConfigFile(ini);
    if (localConfigFile.virgilAccessToken.empty()) {
        localConfigFile.virgilAccessToken = globalConfigFile.virgilAccessToken;
    }

    std::string identityServiceUri = vsdk::ServiceUri::kIdentityServiceUri;
    std::string publicServiceUri = vsdk::ServiceUri::kKeysServiceUri;
    std::string privateServiceUri = vsdk::ServiceUri::kPrivateKeyServiceUri;
    if (localConfigFile.serviceUri.getIdentityService().empty()) {
        identityServiceUri = globalConfigFile.serviceUri.getIdentityService();
    }

    if (localConfigFile.serviceUri.getPublicKeyService().empty()) {
        publicServiceUri = globalConfigFile.serviceUri.getPublicKeyService();
    }

    if (localConfigFile.serviceUri.getPrivateKeyService().empty()) {
        privateServiceUri = globalConfigFile.serviceUri.getPrivateKeyService();
    }

    localConfigFile.serviceUri = virgil::sdk::ServiceUri(identityServiceUri, publicServiceUri, privateServiceUri);
    return localConfigFile;
}
