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
#include <stdexcept>
#include <string>

#include <tclap/CmdLine.h>

#include <virgil/crypto/VirgilByteArray.h>

#include <cli/version.h>
#include <cli/config.h>
#include <cli/pair.h>
#include <cli/util.h>

#ifdef SPLIT_CLI
#define MAIN main
#else
#define MAIN card_search_main
#endif

int MAIN(int argc, char **argv) {
    try {
      std::string description =
            "Get Virgil Public Key from the Virgil Keys service.\n";

        std::vector <std::string> examples;
        examples.push_back(
                "Get pure Virgil Public Key:\n"
                "virgil public-key-get -o virgil_pub.key -e email:user@domain.com\n"
                );

        examples.push_back(
                "Get Virgil Public Key with associated user data:\n"
                "virgil public-key-get -o virgil_pub.key -e email:user@domain.com -k private.key\n"
                );

        std::string descriptionMessage = virgil::cli::getDescriptionMessage(description, examples);


        // Parse arguments.
        TCLAP::CmdLine cmd(descriptionMessage, ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> outArg("o", "out", "Output Virgil Public Key. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> publicKeyIdArg("e", "public-key-id",
                "Virgil Public Key identifier, associated with given Private Key.\n"
                "Format:\n"
                "[id|vkey|email]:<value>\n"
                "where:\n"
                "\t* if id, then <value> - UUID associated with Public Key;\n"
                "\t* if vkey, then <value> - user's Virgil Public Key file stored locally;\n"
                "\t* if email, then <value> - user email associated with Public Key.\n",
                true, "", "arg");

        TCLAP::ValueArg<std::string> privateKeyArg("k", "key", "Private Key. If specified then all"
                " user data associated with Virgil Public Key will be provided.",
                false , "", "file");

        TCLAP::ValueArg<std::string> privatePasswordArg("p", "key-pwd", "Private Key password.",
                false, "", "arg");

        cmd.add(privatePasswordArg);
        cmd.add(privateKeyArg);
        cmd.add(publicKeyIdArg);
        cmd.add(outArg);
        cmd.parse(argc, argv);





    } catch (TCLAP::ArgException& exception) {
        std::cerr << "card-search. Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "card-search. Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
