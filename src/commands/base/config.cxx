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

#include <cli/ConfigFile.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>

namespace vsdk = virgil::sdk;

static std::string configFileName =
#if defined(WIN32)
    "\\virgil-cli.ini";
#else
    "/virgil-cli.conf";
#endif

static std::string getTemplateConfig();

static void createGlobalConfigFile(const bool verbose);

static void createLocalConfigFile(const bool verbose);

static std::string readGlobalConfigFile(const bool verbose);

static std::string readLocalConfigFile(const bool verbose);

int config_main(int argc, char** argv) {
    try {
        std::string description = "Get information about Virgil CLI configuration file.\n\n";

        std::vector<std::string> examples;
        examples.push_back("Show path to the configuration file applied for all users:\n"
                           "virgil config --global --path\n\n");

        examples.push_back("Show path to the configuration file applied for current user:\n"
                           "virgil config --local --path\n\n");

        examples.push_back("Show configuration file template:\n"
                           "virgil config --template\n\n");

        examples.push_back("Create a global configuration file from template:\n"
                           "virgil config --global --create\n\n");

        examples.push_back("Create a local configuration file from template:\n"
                           "virgil config --local --create\n\n");

        examples.push_back("Show the global configuration file:\n"
                           "virgil config --global --list\n\n");

        examples.push_back("Show the local configuration file:\n"
                           "virgil config --local --list\n\n");

        std::string descriptionMessage = cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::SwitchArg isGlobalConfigFileArg("g", "global", "The configuration file applied for all users.", false);

        TCLAP::SwitchArg isLocalConfigFileArg("l", "local", "The configuration file applied for current user.", false);

        TCLAP::SwitchArg showTemplateArg("t", "template", "Show configuration file template.", false);

        TCLAP::SwitchArg createConfigFileArg("c", "create", "Create a configuration file from template.", false);

        TCLAP::SwitchArg showConfigFileArg("", "list", "Show the configuration file.", false);

        TCLAP::SwitchArg showPathConfigFileArg("p", "path", "Show path to the configuration file.", false);

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Shows detailed information.", false);

        cmd.add(verboseArg);
        cmd.add(showPathConfigFileArg);
        cmd.add(showConfigFileArg);
        cmd.add(createConfigFileArg);
        cmd.add(showTemplateArg);
        cmd.add(isLocalConfigFileArg);
        cmd.add(isGlobalConfigFileArg);
        cmd.parse(argc, argv);

        const bool all = isLocalConfigFileArg.getValue() && isGlobalConfigFileArg.getValue();

        if (showPathConfigFileArg.getValue()) {
            std::string pathLocalConfigFile = get_user_config_folder("virgil-cli") + configFileName;
            std::string pathGlobalConfigFile = get_all_user_config_folder("virgil-cli") + configFileName;

            if (all) {
                std::cout << "> Local configuration file path: " << pathLocalConfigFile << "\n";
                std::cout << "> Global configuration file path: " << pathGlobalConfigFile << "\n";
            } else if (isLocalConfigFileArg.getValue()) {
                std::cout << pathLocalConfigFile << "\n";
            } else {
                // isGlobalConfigFileArg
                std::cout << pathGlobalConfigFile << "\n";
            }
        }

        if (createConfigFileArg.getValue()) {
            if (all) {
                createLocalConfigFile(verboseArg.getValue());
                createGlobalConfigFile(verboseArg.getValue());
            } else if (isLocalConfigFileArg.getValue()) {
                createLocalConfigFile(verboseArg.getValue());
            } else {
                // isGlobalConfigFileArg
                createGlobalConfigFile(verboseArg.getValue());
            }
        }

        if (showConfigFileArg.getValue()) {
            if (all) {
                std::cout << readLocalConfigFile(verboseArg.getValue());
                std::cout << readGlobalConfigFile(verboseArg.getValue());
            } else if (isLocalConfigFileArg.getValue()) {
                std::cout << readLocalConfigFile(verboseArg.getValue());
            } else {
                // isGlobalConfigFileArg
                std::cout << readGlobalConfigFile(verboseArg.getValue());
            }
        }

        if (showTemplateArg.getValue()) {
            std::cout << getTemplateConfig();
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "config. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "config. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

std::string getTemplateConfig() {
    cli::ConfigFile defaultConfig;
    std::string config;
    config += "; First, you must create a free Virgil Security developer's account by signing up\n"
              "; here - https://developer.virgilsecurity.com/account/signup. Once you have your\n"
              "; account you can sign in and generate an access token for your application.\n"
              ";\n"
              "; The access token provides authenticated secure access to Virgil Keys Services and is passed with\n"
              "; every API call. The access token also allows the API to associate your app’s requests with your\n"
              "; Virgil Security developer's account.\n\n"

              "[Virgil Access Token]\n";
    config += "token=<VIRGIL_ACCESS_TOKEN>\n\n";

    config += "; This class provide base URIs for the Virgil Security services\n"
              "[URI]\n\n"

              "; Base URI of the Virgil Identity Service\n"
              "identity-service=";
    config += defaultConfig.serviceUri.getIdentityService() + "\n\n";

    config += "; base URI of the Virgil Keys Service\n"
              "public-key-service=";
    config += defaultConfig.serviceUri.getPublicKeyService() + "\n\n";

    config += "; base URI of the Virgil Private Service\n"
              "private-key-service=";
    config += defaultConfig.serviceUri.getPrivateKeyService() + "\n";

    return config;
}

void createGlobalConfigFile(const bool verbose) {
    std::string pathGlobalConfigFile = get_all_user_config_folder("virgil-cli") + configFileName;
    cli::writeOutput(pathGlobalConfigFile, getTemplateConfig());
    if (verbose) {
        std::cout << "Create a global configuration file from template by path:" + pathGlobalConfigFile << "\n";
    }
}

void createLocalConfigFile(const bool verbose) {
    std::string pathLocalConfigFile = get_user_config_folder("virgil-cli") + configFileName;
    cli::writeOutput(pathLocalConfigFile, getTemplateConfig());
    if (verbose) {
        std::cout << "Create a local configuration file from template by path:" + pathLocalConfigFile << "\n";
    }
}

std::string readGlobalConfigFile(const bool verbose) {
    std::string pathGlobalConfigFile = get_all_user_config_folder("virgil-cli") + configFileName;
    std::ifstream inGlobalConfigFile(pathGlobalConfigFile, std::ios::in | std::ios::binary);
    if (!inGlobalConfigFile) {
        throw std::invalid_argument("Can't read a global configuration file by path:" + pathGlobalConfigFile);
    }
    if (verbose) {
        std::cout << "Read a global config file"
                  << "\n";
    }
    return std::string((std::istreambuf_iterator<char>(inGlobalConfigFile)), std::istreambuf_iterator<char>());
}

std::string readLocalConfigFile(const bool verbose) {
    std::string pathLocalConfigFile = get_user_config_folder("virgil-cli") + configFileName;
    std::ifstream inLocalConfigFile(pathLocalConfigFile, std::ios::in | std::ios::binary);
    if (!inLocalConfigFile) {
        throw std::invalid_argument("Can't read a local configuration file by path:" + pathLocalConfigFile);
    }
    if (verbose) {
        std::cout << "Read a local configuration file"
                  << "\n";
    }
    return std::string((std::istreambuf_iterator<char>(inLocalConfigFile)), std::istreambuf_iterator<char>());
}
