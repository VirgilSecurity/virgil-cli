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

#include <iostream>
#include <vector>

#include <tclap/CmdLine.h>

#include <filesystem/path.h>

#include <cli/ConfigFile.h>
#include <cli/version.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>

namespace vsdk = virgil::sdk;

static const std::string configFileName =
#if defined(WIN32)
    "\\virgil-cli.ini";
#else
    "/virgil-cli.conf";
#endif

static void checkUnlabelValueArgs(const std::vector<std::string>& args);
static void createConfigFile(const std::string& type, const std::string& value, const bool isGlobal);
static bool isConfigFileExist(const std::string& path);
static void showConfigFile(const std::string& path);

int config_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples{"1. Show path to the configuration file applied for all users:\n"
                                          "\tvirgil config --global --path\n\n",

                                          "1.1 Show path to the configuration file applied for current user:\n"
                                          "\tvirgil config --local --path\n\n",

                                          "2. Show the global configuration file:\n"
                                          "\tvirgil config --global --list\n\n",

                                          "2.1 Show the local configuration file:\n"
                                          "\tvirgil config --local --list\n\n",

                                          "3. Set Virgil Access Token in configuration file:\n"
                                          "\tvirgil config --global token <VIRGIL_ACCESS_TOKEN>\n\n",

                                          "3.1 Set Virgil Access Token in configuration file:\n"
                                          "\tvirgil config --local token <VIRGIL_ACCESS_TOKEN>\n"};

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kConfig_Description, examples);
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());
        TCLAP::SwitchArg isGlobalArg("g", "global", "The configuration file applied for all users.", false);
        TCLAP::SwitchArg isLocalArg("l", "local", "The configuration file applied for current user.", false);
        TCLAP::SwitchArg showConfigFileArg("", "list", "Show the configuration file.", false);
        TCLAP::SwitchArg showPathConfigFileArg("p", "path", "Show path to the configuration file.", false);
        TCLAP::UnlabeledMultiArg<std::string> valueArgs("value", "", false, "value", false);

        cmd.add(valueArgs);
        cmd.add(showPathConfigFileArg);
        cmd.add(showConfigFileArg);
        cmd.xorAdd(isGlobalArg, isLocalArg);
        cmd.parse(argc, argv);

        auto unlabelArgs = valueArgs.getValue();
        if (!unlabelArgs.empty()) {
            checkUnlabelValueArgs(unlabelArgs);
            std::string type = unlabelArgs.at(0);
            std::string value = unlabelArgs.at(1);
            createConfigFile(type, value, isGlobalArg.isSet());
            return EXIT_SUCCESS;
        }

        std::string pathFolderConfigFile =
            isGlobalArg.isSet() ? get_all_user_config_folder("virgil-cli") : get_user_config_folder("virgil-cli");

        std::string pathConfigFile = pathFolderConfigFile + configFileName;
        if ((showConfigFileArg.isSet() || showPathConfigFileArg.isSet()) && !isConfigFileExist(pathConfigFile)) {
            std::string applied = isGlobalArg.isSet() ? "--global" : "--local";
            auto error = std::string("There is no configuration file. Use virgil config ") + applied +
                         " token <token> to create it.";
            throw std::runtime_error(error);
        }

        const bool isShowAll = showConfigFileArg.isSet() && showPathConfigFileArg.isSet();
        if (isShowAll) {
            std::string globalSupportInfo = "; Global configuration file path: " + pathConfigFile;
            std::string localSupportInfo = "; Local configuration file path: " + pathConfigFile;
            std::cout << (isGlobalArg.isSet() ? globalSupportInfo : localSupportInfo) << std::endl;
            showConfigFile(pathConfigFile);
        } else if (showConfigFileArg.isSet()) {
            showConfigFile(pathConfigFile);
        } else if (showPathConfigFileArg.isSet()) {
            std::cout << pathConfigFile << std::endl;
        } else {
            throw std::runtime_error("Required argument[s] missing: list or/and path.");
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "config. Error. " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "config. Error. " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void checkUnlabelValueArgs(const std::vector<std::string>& args) {
    if (args.size() != 2) {
        throw std::invalid_argument("must be to one 'key value'");
    }

    std::string type = args.at(0);
    std::string value = args.at(1);
    if (type != "token" && type != "uri.identity" && type != "uri.public-key" && type != "uri.private-key") {
        throw std::runtime_error("key does not contain a section: " + type + " " + value);
    }
}

void createConfigFile(const std::string& type, const std::string& value, const bool isGlobal) {
    std::string pathFolderConfigFile =
        isGlobal ? get_all_user_config_folder("virgil-cli") : get_user_config_folder("virgil-cli");

    if (!filesystem::path(pathFolderConfigFile).is_directory()) {
        filesystem::create_directory(pathFolderConfigFile);
    }

    const std::string pathConfigFile = pathFolderConfigFile + configFileName;
    cli::ConfigFile configFile;
    if (filesystem::path(pathConfigFile).is_file()) {
        cli::ConfigFile existConfigFile = cli::readConfigFile(pathConfigFile);
        configFile = existConfigFile;
    }

    if (type == "token") {
        configFile.virgilAccessToken = value;
    } else if (type == "uri.identity") {
        configFile.identityUrl = value;
    } else if (type == "uri.public-key") {
        configFile.publicKeyUrl = value;
    } else if (type == "uri.private-key") {
        configFile.privateKeyUrl = value;
    } else {
        return;
    }

    cli::writeConfigFile(configFile, pathConfigFile);
}

bool isConfigFileExist(const std::string& path) {
    return filesystem::path(path).exists() && filesystem::path(path).is_file();
}

void showConfigFile(const std::string& path) {
    std::cout << cli::configFile2ini(cli::readConfigFile(path)) << std::endl;
}