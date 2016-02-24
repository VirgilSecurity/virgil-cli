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

#include <virgil/crypto/VirgilByteArray.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>

using virgil::crypto::VirgilByteArray;

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN card_sign_main
#endif

int MAIN(int argc, char **argv) {
    try {
        std::string description = "Get user's Private Key from the Virgil Private Keys service.\n";

        std::vector <std::string> examples;
        examples.push_back(
                "Container type 'easy':\n"
                "virgil private-key-get -u email:user@domain.com -n container_pwd\n");

        examples.push_back(
                "Container type 'normal':\n"
                "virgil private-key-get -u email:user@domain.com -n container_pwd -w wrapper_pwd\n");

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);

        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Private Key. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> userIdArg("u","user-id",
                "User identifier, associated with container.\n"
                "Format:\n"
                "[email]:<value>\n"
                "where:\n"
                "\t* if email, then <value> - user email associated with Public Key.\n",
                true, "","arg" );

        TCLAP::ValueArg<std::string> containerPaswordArg("n", "container-pwd", "Container password.",
                true, "", "arg");

        TCLAP::ValueArg<std::string> wrapperPaswordArg("w", "wrapper-pwd",
                "Password is used to encrypt Private Key before it will be send to the."
                "Virgil Private Keys Service.\n"
                "Note, MUST be used only if container type is `normal`.\n"
                "Note, MUST be managed by user, because it can not be reset or recovered.",
                false, "", "arg");

        cmd.add(wrapperPaswordArg);
        cmd.add(containerPaswordArg);
        cmd.add(userIdArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);


    } catch (TCLAP::ArgException& exception) {
        std::cerr << "private-key-get. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "private-key-get. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
