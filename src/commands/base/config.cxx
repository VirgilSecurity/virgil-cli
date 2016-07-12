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

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <tclap/CmdLine.h>

#include <cli/ConfigFile.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>

namespace vsdk = virgil::sdk;
namespace vcli = virgil::cli;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN config_main
#endif

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Get information about Virgil CLI configuration file.\n\n";

        std::vector<std::string> examples;
        examples.push_back("Show path to the configuration file applied for all users:\n"
                           "virgil config --global\n\n");

        examples.push_back("Show path to the configuration file applied for current user:\n"
                           "virgil config --local\n\n");

        examples.push_back("Show configuration file template:\n"
                           "virgil config --template\n\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "If omitted, stdout is used.\n", false, "", "file");

        TCLAP::SwitchArg showGlobalConfigFilePathArg(
            "g", "global", "Show path to the configuration file applied for all users.", false);

        TCLAP::SwitchArg showLocalConfigFilePathArg(
            "l", "local", "Show path to the configuration file applied for current user.", false);

        TCLAP::SwitchArg showTemplateArg("t", "template", "Show configuration file template.", false);

        cmd.add(showTemplateArg);
        cmd.add(showLocalConfigFilePathArg);
        cmd.add(showGlobalConfigFilePathArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        std::string configFileName =
#if defined(WIN32)
            "\\virgil-cli.ini";
#else
            "/virgil-cli.conf";
#endif

        const bool showAll = !showGlobalConfigFilePathArg.getValue() && !showLocalConfigFilePathArg.getValue() &&
                             !showTemplateArg.getValue();

        const bool isMultipleInfo = showAll ||
                                    (showGlobalConfigFilePathArg.getValue() && showLocalConfigFilePathArg.getValue()) ||
                                    (showGlobalConfigFilePathArg.getValue() && showTemplateArg.getValue()) ||
                                    (showLocalConfigFilePathArg.getValue() && showTemplateArg.getValue());

        std::string data;
        if (showGlobalConfigFilePathArg.getValue() || showAll) {
            std::string pathGlobalConfigFile = get_all_user_config_folder("virgil-cli") + configFileName;
            data += (isMultipleInfo ? "> Global configuration file path: " : "") + pathGlobalConfigFile + "\n";
        }

        if (showLocalConfigFilePathArg.getValue() || showAll) {
            std::string pathLocalConfigFile = get_user_config_folder("virgil-cli") + configFileName;
            data += (isMultipleInfo ? "> Local configuration file path: " : "") + pathLocalConfigFile + "\n";
        }

        if (showTemplateArg.getValue() || showAll) {
            vcli::ConfigFile defaultConfig;
            std::string config = isMultipleInfo ? "> Configuration file template:\n" : "";
            config +=
                "; First, you must create a free Virgil Security developer's account by signing up\n"
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

            data += config;
        }

        vcli::writeOutput(outArg.getValue(), data);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "config. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "config. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
