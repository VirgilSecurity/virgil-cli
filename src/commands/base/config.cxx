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

#include <fstream>
#include <iostream>
#include <vector>

#include <tclap/CmdLine.h>

#include <filesystem/path.h>
#include <filesystem/resolver.h>

#include <cli/ConfigFile.h>
#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>

namespace vsdk = virgil::sdk;

static const std::string configFileName =
#if defined(WIN32)
        "\\virgil-cli.ini";
#else
        "/virgil-cli.conf";
#endif

static void checkUnlabelValueArgs(const std::vector<std::string> &args);
static void createConfigFile(const std::string &type, const std::string &value, const bool isGlobal);
static bool isConfigFileExist(const bool isGlobal, const std::string& path);

int config_main(int argc, char **argv) {
    try {
        std::string description = "Get information about Virgil CLI configuration file.\n";

        std::vector<std::string> examples;
        examples.push_back("Show path to the configuration file applied for all users:\n"
                                   "virgil config --global --path\n");

        examples.push_back("Show path to the configuration file applied for current user:\n"
                                   "virgil config --local --path\n");

        examples.push_back("Show the global configuration file:\n"
                                   "virgil config --global --list\n");

        examples.push_back("Show the local configuration file:\n"
                                   "virgil config --local --list\n");

        examples.push_back("Set Virgil Access Token in configuration file:\n"
                                   "virgil config --global token=<VIRGIL_ACCESS_TOKEN>\n");

        examples.push_back("Set Virgil Access Token in configuration file:\n"
                                   "virgil config --local token=<VIRGIL_ACCESS_TOKEN>\n");

        std::string descriptionMessage = cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        TCLAP::SwitchArg isGlobalConfigFileArg("g", "global", "The configuration file applied for all users.", false);

        TCLAP::SwitchArg isLocalConfigFileArg("l", "local", "The configuration file applied for current user.", false);

        TCLAP::SwitchArg showConfigFileArg("", "list", "Show the configuration file.", false);

        TCLAP::SwitchArg showPathConfigFileArg("p", "path", "Show path to the configuration file.", false);

        TCLAP::UnlabeledMultiArg<std::string> valueArgs("value", "", false, "value", false);

        cmd.add(valueArgs);
        cmd.add(showPathConfigFileArg);
        cmd.add(showConfigFileArg);
        cmd.xorAdd(isGlobalConfigFileArg, isLocalConfigFileArg);
        cmd.add(verboseArg);
        cmd.parse(argc, argv);

        bool isGlobal = false;
        if (isGlobalConfigFileArg.isSet()) {
            isGlobal = isGlobalConfigFileArg.getValue();
        }

        if (isLocalConfigFileArg.isSet()) {
            isGlobal = !isLocalConfigFileArg.getValue();
        }

        auto unlabelArgs = valueArgs.getValue();
        if ( ! unlabelArgs.empty()) {
            checkUnlabelValueArgs(unlabelArgs);
            std::string type = unlabelArgs.at(0);
            std::string value = unlabelArgs.at(1);
            createConfigFile(type, value, isGlobal);
        }

        std::string pathFolderConfigFile = isGlobal ?
                                           get_all_user_config_folder("virgil-cli") :
                                           get_user_config_folder("virgil-cli");

        std::string pathConfigFile = pathFolderConfigFile + configFileName;

        if (showConfigFileArg.isSet() && showConfigFileArg.getValue()) {
            auto configFile = cli::readConfigFile(pathConfigFile);
            std::string data = cli::configFile2ini(configFile);
            std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));
            std::cout << std::endl;
        }

        if (showPathConfigFileArg.isSet() && showPathConfigFileArg.getValue()) {
            if (isConfigFileExist(isGlobal, pathConfigFile)) {
                std::cout << pathConfigFile << std::endl;
            } else {
                std::cout << pathConfigFile << " path is shown although is doesn't exist." << std::endl;
            }
        }

    } catch (TCLAP::ArgException &exception) {
        std::cerr << "config. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception &exception) {
        std::cerr << "config. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void checkUnlabelValueArgs(const std::vector<std::string> &args) {
    if (args.size() > 2 || args.size() < 2) {
        throw std::invalid_argument("must be to one 'key value'");
    }

    std::string type = args.at(0);
    std::string value = args.at(1);
    if (type != "token" && type != "uri.identity" && type != "uri.public-key" && type != "uri.private-key") {
        throw std::runtime_error("key does not contain a section: " + type + " " + value);
    }
}

void createConfigFile(const std::string &type, const std::string &value, const bool isGlobal) {
    std::string pathFolderConfigFile = isGlobal ? get_all_user_config_folder("virgil-cli") : get_user_config_folder(
            "virgil-cli");

    filesystem::path pathDirectory(pathFolderConfigFile);
    const bool isDirectoryConfigFile = pathDirectory.is_directory();
    cli::ConfigFile configFile;
    if (!isDirectoryConfigFile) {
        filesystem::create_directory(pathDirectory);
    }

    const std::string pathConfigFile = pathFolderConfigFile + configFileName;
    filesystem::path pathFile(pathConfigFile);
    const bool isConfigFile = pathFile.is_file();
    if (isConfigFile) {
        cli::ConfigFile existConfigFile = cli::readConfigFile(pathConfigFile);
        configFile = existConfigFile;
    }

    if (type == "token") {
        configFile.virgilAccessToken = value;
    } else if (type == "uri.identity") {
        configFile.setIdentityUrl(value);
    } else if (type == "uri.public-key") {
        configFile.setPublicKeyUrl(value);
    } else {
        // type == uri.private-key
        configFile.setPrivateKeyUrl(value);
    }

    cli::writeConfigFile(configFile, pathConfigFile);
}

static bool isConfigFileExist(const bool isGlobal, const std::string& path) {
    std::string pathFolderConfigFile = isGlobal ? get_all_user_config_folder("virgil-cli")
                                                : get_user_config_folder(
                    "virgil-cli");

    filesystem::path pathDirectory(pathFolderConfigFile);
    const bool isDirectoryConfigFile = pathDirectory.is_directory();

    const std::string pathConfigFile = pathFolderConfigFile + configFileName;
    filesystem::path pathFile(pathConfigFile);
    const bool isConfigFile = pathFile.is_file();

    return isDirectoryConfigFile && isConfigFile;
}