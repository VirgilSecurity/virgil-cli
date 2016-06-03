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

#include <iostream>
#include <stdexcept>
#include <string>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/util/token.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/version.h>
#include <cli/pair.h>
#include <cli/util.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;
namespace vcli = virgil::cli;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN identity_confirm_private_main
#endif

int MAIN(int argc, char** argv) {
    try {
        std::string description = "Provides helper methods to generate validation token based on the"
                                  "application's private key. It is required for the following"
                                  "operations:\n"
                                  "1. create a Private Virgil Card with a confirmed Identity. "
                                  "See 'virgil card-create-private';\n"
                                  "2. revoke a Private Virgil Card, a group of Cards."
                                  "See 'virgil card-revoke-private', 'virgil public-key-revoke';\n"
                                  "3. get a Private key from the Private Keys Service."
                                  "See 'virgil private-key-get'.\n\n";

        std::vector<std::string> examples;
        examples.push_back(
            "Generate a validation-token:\n"
            "virgil identity-confirm-private -d <identity_value> -t <identity_type> -o private-validated-identity.txt "
            "--app-key application-private.key\n\n");

        examples.push_back(
            "Generate a validation-token with obfuscated identity (see 'virgil hash'):\n"
            "virgil identity-confirm-private -d <obfuscate_value> -t <obfuscate_type> -o validated-identity.txt "
            "--app-key application-private.key\n\n");

        std::string descriptionMessage = vcli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "validation-token",
                                            "A Validated Identity. If omitted, stdout is used.", false, "", "file");

        TCLAP::ValueArg<std::string> identityArg("d", "identity", "Identity value", true, "", "arg");

        TCLAP::ValueArg<std::string> identityTypeArg("t", "identity-type", "Identity type", true, "", "arg");

        TCLAP::ValueArg<std::string> appPrivateKeyArg("", "app-key", "Application Private key", true, "", "file");

        TCLAP::ValueArg<std::string> appPrivateKeyPasswordArg(
            "", "app-key-password", "Password to be used for Application Private Key encryption.", false, "", "arg");

        TCLAP::SwitchArg verboseArg("V", "VERBOSE", "Show detailed information", false);

        cmd.add(verboseArg);
        cmd.add(appPrivateKeyPasswordArg);
        cmd.add(appPrivateKeyArg);
        cmd.add(identityTypeArg);
        cmd.add(identityArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        std::string identityValue = identityArg.getValue();
        std::string identityType = identityTypeArg.getValue();

        std::string pathPrivateKey = appPrivateKeyArg.getValue();
        vcrypto::VirgilByteArray privateKey = vcli::readPrivateKey(pathPrivateKey);
        vcrypto::VirgilByteArray privateKeyPassword;
        if (appPrivateKeyPasswordArg.isSet()) {
            privateKeyPassword = vcrypto::str2bytes(appPrivateKeyPasswordArg.getValue());
        } else {
            privateKeyPassword = vcli::setPrivateKeyPass(privateKey);
        }
        vsdk::Credentials appCredentials(privateKey, privateKeyPassword);

        if (verboseArg.isSet()) {
            std::cout << "Generating validation token.." << std::endl;
        }

        std::string validationToken =
            vsdk::util::generate_validation_token(identityValue, identityType, appCredentials);

        vsdk::dto::ValidatedIdentity validatedIdentity(vsdk::dto::Identity(identityValue, identityType),
                                                       validationToken);

        std::string validatedIdentityStr =
            vsdk::io::Marshaller<vsdk::dto::ValidatedIdentity>::toJson<4>(validatedIdentity);

        vcli::writeOutput(outArg.getValue(), validatedIdentityStr);

        if (verboseArg.isSet()) {
            std::cout << "The validated-identity for a Private Virgil Card generated" << std::endl;
        }

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "identity-confirm-private. Error: " << exception.error() << " for arg " << exception.argId()
                  << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "identity-confirm-private. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
