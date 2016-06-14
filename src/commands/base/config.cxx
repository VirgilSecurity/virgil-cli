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
        examples.push_back("Get path to a configuration file for current user:\n"
                           "virgil config --local\n\n");

        examples.push_back("Get path to the configuration file for all users:\n"
                           "virgil config --global\n\n");

        examples.push_back("Get a template a configuration file:\n"
                           "virgil config --template\n\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "If omitted, stdout is used.\n", false, "", "file");

        TCLAP::SwitchArg isGetGlobalConfigFileArg("", "global", "Get path to the configuration file for all users.",
                                                  false);

        TCLAP::SwitchArg isGetLocalConfigFileArg("", "local", "Get path to the configuration file for current user.",
                                                 false);

        TCLAP::SwitchArg templateArg("", "template", "Get a template configuration file.", false);

        cmd.add(templateArg);
        cmd.add(isGetLocalConfigFileArg);
        cmd.add(isGetGlobalConfigFileArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        std::string configFileName;
#if defined(WIN32)
        configFileName = "\\virgil-cli.ini";
#else
        configFileName = "/virgil-cli.conf";
#endif

        std::string data;
        if (isGetLocalConfigFileArg.getValue()) {
            std::string pathLocalConfigFile = get_user_config_folder("virgil-cli") + configFileName;
            data += pathLocalConfigFile + "\n";
        }

        if (isGetGlobalConfigFileArg.getValue()) {
            std::string pathGlobalConfigFile = get_all_user_config_folder("virgil-cli") + configFileName + "\n";
            data += pathGlobalConfigFile + "\n";
        }

        if (templateArg.getValue()) {
            vcli::ConfigFile defaultConfig;
            std::string config =
                "; First, you must create a free Virgil Security developer's account by signing up\n"
                "; here - https://developer.virgilsecurity.com/account/signup. Once you have your\n"
                "; account you can sign in and generate an access token for your application.\n\n"

                "; The access token provides authenticated secure access to Virgil Keys Services and is passed with\n"
                "; every API call. The access token also allows the API to associate your app’s requests with your\n"
                "; Virgil Security developer's account.\n\n"

                "[Virgil Access Token]\n";

            config += "token=<VIRGIL_ACCESS_TOKEN>\n";

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
