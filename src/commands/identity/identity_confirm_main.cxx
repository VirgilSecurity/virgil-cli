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
#include <string>
#include <stdexcept>

#include <tclap/CmdLine.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;
namespace vcli = virgil::cli;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN identity_confirm_main
#endif

int MAIN(int argc, char **argv) {
    try {
        std::string description = "Confirm identity\n";

        std::vector <std::string> examples;
        examples.push_back(
                "Identity confirm:\n"
                "virgil identity-confirm  -q d6b4abd9-057c-4d01-bdec-7b2ab232e2af -w B4L7O2\n");

        examples.push_back(
                "Identity confirm:\n"
                "virgil identity-confirm  -q d6b4abd9-057c-4d01-bdec-7b2ab232e2af -w B4L7O2 "
                "-l 3600 -r 10\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Validated identity. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> actionIdArg("q", "action-id", "Action id.",
                true, "", "file");

        TCLAP::ValueArg<std::string> confirmationCodeArg("w", "confirmation-code", "Confirmation code",
                true, "", "file");

        TCLAP::ValueArg<int> timeToliveArg("l", "time-to-live", "Time to live, default 3600.",
                false, 3600, "int");

        TCLAP::ValueArg<int> countToLiveArg("r", "count-to-live", "Count to live, default 10.",
                false, 50, "int");

        cmd.add(countToLiveArg);
        cmd.add(timeToliveArg);
        cmd.add(confirmationCodeArg);
        cmd.add(actionIdArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);

        vsdk::ServicesHub servicesHub(VIRGIL_ACCESS_TOKEN);

        vsdk::model::ValidatedIdentity validatedIdentity =
            servicesHub.identity().confirm(actionIdArg.getValue(), confirmationCodeArg.getValue(),
                    timeToliveArg.getValue(), countToLiveArg.getValue());

        std::string validatedIdentityStr =
            vsdk::io::Marshaller<vsdk::model::ValidatedIdentity>::toJson<4>(validatedIdentity);

        vcli::writeBytes(outArg.getValue(), validatedIdentityStr);

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "identity-confirm. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "identity-confirm. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
