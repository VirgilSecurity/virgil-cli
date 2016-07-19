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

#include <tclap/CmdLine.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>
#include <cli/DescUtils/all.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

int public_key_get_main(int argc, char** argv) {
    try {
        std::vector<std::string> examples;
        examples.push_back("Get a public key by its `public-key-id`:\n"
                           "virgil public-key-get -o alice/public.key -e <public_key_id>\n\n");

        std::string descriptionMessage = cli::getDescriptionMessage(cli::kPublicKeyGet_Description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', cli::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Virgil Public Key. If omitted, stdout is used.", false, "",
                                            "file");

        TCLAP::ValueArg<std::string> publicKeyIdArg(cli::kPublicKeyId_ShortName, cli::kPublicKeyId_LongName,
                                                    cli::kPublicKeyId_Description, true, "",
                                                    cli::kPublicKeyId_TypeDesc);

        TCLAP::SwitchArg verboseArg(cli::kVerbose_ShortName, cli::kVerbose_LongName, cli::kVerbose_Description, false);

        cmd.add(verboseArg);
        cmd.add(publicKeyIdArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        cli::ConfigFile configFile = cli::readConfigFile();
        vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.getServiceUri());

        std::string publicKeyId = publicKeyIdArg.getValue();

        vsdk::models::PublicKeyModel publicKey = servicesHub.publicKey().get(publicKeyId);
        std::string publicKeyStr = vsdk::io::Marshaller<vsdk::models::PublicKeyModel>::toJson<4>(publicKey);
        cli::writeBytes(outArg.getValue(), publicKeyStr);

        if (verboseArg.isSet()) {
            std::cout << "Public key by public-key-id:" << publicKeyIdArg.getValue() << " has been received"
                      << std::endl;
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "public-key-get. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "public-key-get. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
