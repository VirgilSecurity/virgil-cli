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
#include <sstream>
#include <fstream>

#include <ini_parser/ini.hpp>
#include <cli/ConfigFile.h>
#include <cli/util.h>

namespace vsdk = virgil::sdk;

cli::ConfigFile cli::iniToConfigFile(const std::string& ini) {
    try {
        std::stringstream ss(ini);
        INI::Parser iniParser(ss);

        cli::ConfigFile configFile;
        configFile.virgilAccessToken = iniParser.top()["token"];
        configFile.setServiceUri(vsdk::ServiceUri(iniParser.top()("uri")["identity"],
                                                  iniParser.top()("uri")["public-key"],
                                                  iniParser.top()("uri")["private-key"]));
        return configFile;

    } catch (std::runtime_error& exception) {
        std::string error = "Can't parse config file: " + ini + "\n";
        error += exception.what();
        throw std::runtime_error(error);
    }
}

std::string cli::configFile2ini(const cli::ConfigFile& configFile) {
    std::string data;
    if (!configFile.virgilAccessToken.empty()) {
        data += "token=" + configFile.virgilAccessToken + "\n";
    }

    const bool isUrls =
        !configFile.identityUrl.empty() || !configFile.publicKeyUrl.empty() || !configFile.privateKeyUrl.empty();
    if (isUrls) {
        data += "[uri]\n";
    }

    if (!configFile.identityUrl.empty()) {
        data += "identity=" + configFile.identityUrl + "\n";
    }

    if (!configFile.publicKeyUrl.empty()) {
        data += "public-key=" + configFile.publicKeyUrl + "\n";
    }

    if (!configFile.privateKeyUrl.empty()) {
        data += "private-key=" + configFile.privateKeyUrl + "\n";
    }
    return data;
}

static cli::ConfigFile readGlobalConfigFile(const std::string& pathGlobalConfigFile) {
    std::ifstream inGlobalConfigFile(pathGlobalConfigFile, std::ios::in | std::ios::binary);
    if (!inGlobalConfigFile) {
        return cli::ConfigFile();
    }

    std::string ini((std::istreambuf_iterator<char>(inGlobalConfigFile)), std::istreambuf_iterator<char>());
    return cli::iniToConfigFile(ini);
}

cli::ConfigFile cli::readConfigFile() {
    std::string configFileName =
#if defined(WIN32)
        "\\virgil-cli.ini";
#else
        "/virgil-cli.conf";
#endif

    std::string pathGlobalConfigFile = get_all_user_config_folder("virgil-cli") + configFileName;
    std::string pathLocalConfigFile = get_user_config_folder("virgil-cli") + configFileName;

    cli::ConfigFile globalConfigFile = readGlobalConfigFile(pathGlobalConfigFile);

    std::ifstream inLocalConfigFile(pathLocalConfigFile, std::ios::in | std::ios::binary);
    if (!inLocalConfigFile) {
        if (globalConfigFile.virgilAccessToken.empty()) {
            throw std::runtime_error("The Virgil Access Token was not set. See 'virgil config' for details.");
        }

        return globalConfigFile;
    }

    std::string ini((std::istreambuf_iterator<char>(inLocalConfigFile)), std::istreambuf_iterator<char>());
    cli::ConfigFile localConfigFile = iniToConfigFile(ini);

    if (localConfigFile.virgilAccessToken.empty()) {
        if (globalConfigFile.virgilAccessToken.empty()) {
            throw std::runtime_error("The Virgil Access Token was not set. See 'virgil config' for details.");
        }
        localConfigFile.virgilAccessToken = globalConfigFile.virgilAccessToken;
    }

    if (localConfigFile.identityUrl.empty()) {
        localConfigFile.identityUrl = globalConfigFile.identityUrl;
    } else {
        localConfigFile.identityUrl = localConfigFile.identityUrl;
    }

    if (localConfigFile.publicKeyUrl.empty()) {
        localConfigFile.publicKeyUrl = globalConfigFile.publicKeyUrl;
    } else {
        localConfigFile.publicKeyUrl = localConfigFile.publicKeyUrl;
    }

    if (localConfigFile.privateKeyUrl.empty()) {
        localConfigFile.privateKeyUrl = globalConfigFile.privateKeyUrl;
    } else {
        localConfigFile.privateKeyUrl = localConfigFile.privateKeyUrl;
    }

    return localConfigFile;
}

cli::ConfigFile cli::readConfigFile(const std::string& path) {
    std::string configFileStr = cli::readFile(path);
    return iniToConfigFile(configFileStr);
}

void cli::writeConfigFile(const cli::ConfigFile& configFile, const std::string& path) {
    std::string data = cli::configFile2ini(configFile);
    std::ofstream outFile(path, std::ios::out | std::ios::binary);
    if (!outFile) {
        throw std::invalid_argument("can not write file: " + path);
    }
    outFile << data;
}