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

#ifndef SPLIT_CLI

#include <iostream>
#include <string>
#include <map>
#include <fstream>
#include <iterator>

#include <cli/version.h>
#include <cli/util.h>

typedef int (*main_func)(int argc, char** argv);

// simple-action
int hash_main(int argc, char** argv);
int keygen_main(int argc, char** argv);
int key2pub_main(int argc, char** argv);
int encrypt_main(int argc, char** argv);
int decrypt_main(int argc, char** argv);
int sign_main(int argc, char** argv);
int verify_main(int argc, char** argv);

// module-action
int identity_verify_main(int argc, char** argv);
int identity_confirm_main(int argc, char** argv);
int identity_valid_main(int argc, char** argv);

int card_create_main(int argc, char** argv);
int card_get_main(int argc, char** argv);
int card_search_main(int argc, char** argv);
int card_search_app_main(int argc, char** argv);
int card_sign_main(int argc, char** argv);
int card_unsign_main(int argc, char** argv);
int card_revoke_main(int argc, char** argv);

int public_key_get_main(int argc, char** argv);
int public_key_revoke_main(int argc, char** argv);

int private_key_add_main(int argc, char** argv);
int private_key_get_main(int argc, char** argv);
int private_key_del_main(int argc, char** argv);

static void print_usage(std::ostream& out, const char* programName);

int main(int argc, char** argv) {
    // Parse arguments.
    if (argc < 2) {
        std::cerr << "Error: "
                  << " Required argument is missing: "
                  << "command" << std::endl;
        print_usage(std::cerr, argv[0]);
        return EXIT_FAILURE;
    }

    std::string firstArg(argv[1]);
    if (firstArg == "-h" || firstArg == "--help") {
        print_usage(std::cout, argv[0]);
        return EXIT_SUCCESS;
    } else if (firstArg == "--version") {
        virgil::cli::printVersion(std::cout, argv[0]);
        return EXIT_SUCCESS;
    }

    std::map<std::string, main_func> commandsMap;
    // simple-action
    commandsMap["hash"] = &hash_main;
    commandsMap["keygen"] = &keygen_main;
    commandsMap["key2pub"] = &key2pub_main;
    commandsMap["encrypt"] = &encrypt_main;
    commandsMap["decrypt"] = &decrypt_main;
    commandsMap["sign"] = &sign_main;
    commandsMap["verify"] = &verify_main;

    // module-action
    commandsMap["identity-verify"] = &identity_verify_main;
    commandsMap["identity-confirm"] = &identity_confirm_main;
    commandsMap["identity-valid"] = &identity_valid_main;

    commandsMap["card-create"] = &card_create_main;
    commandsMap["card-get"] = &card_get_main;
    commandsMap["card-search"] = &card_search_main;
    commandsMap["card-search-app"] = &card_search_app_main;
    commandsMap["card-sign"] = &card_sign_main;
    commandsMap["card-unsign"] = &card_unsign_main;
    commandsMap["card-revoke"] = &card_revoke_main;

    commandsMap["public-key-get"] = &public_key_get_main;
    commandsMap["public-key-revoke"] = &public_key_revoke_main;

    commandsMap["private-key-add"] = &private_key_add_main;
    commandsMap["private-key-get"] = &private_key_get_main;
    commandsMap["private-key-del"] = &private_key_del_main;

    auto module = commandsMap.find(firstArg);
    if (module != commandsMap.end()) {
        module->second(argc - 1, argv + 1);
    } else {
        std::cerr << "Error: "
                  << "command '" << firstArg << "' not found" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void print_usage(std::ostream& out, const char* programName) {
    std::string doc = "command [command_opts] [command_args]\n"
                      "DESCRIPTION:\n"
                      "The 'virgil' program is a command line tool for using Virgil Security\n"
                      "stack functionality:\n"
                      "encrypt, decrypt, sign and verify data;\n"
                      "interact with Virgil Keys Service;\n"
                      "interact with Virgil Private Keys Service.\n\n"

                      "COMMON COMMANDS:\n"
                      "hash                        Derives the obfuscated data from incoming parameters using\n"
                      "                            PBKDF function.\n\n"

                      "keygen                      Generate private key with given parameters.\n\n"

                      "key2pub                     Extract Public Key from the Private Key.\n\n"

                      "encrypt                     Encrypt data for given recipients which can be\n"
                      "                            defined by Virgil Public Keys and by passwords.\n\n"

                      "decrypt                     Decrypt data for given recipient which can be\n"
                      "                            defined by Virgil Public Key or by password.\n\n"

                      "sign                        Sign data with Private Key.\n\n"

                      "verify                      Verify data with Virgil Public Key.\n\n\n"

                      "virgil CARD COMMANDS:\n"

                      "card-create                 Create card\n\n"

                      "card-revoke                 Revoke Card\n\n"

                      "card-search                 Search by criteria\n\n"

                      "card-search-app             Search an Application Card\n\n"

                      "card-get                    Get user's Virgil Card/Cards\n\n"

                      "card-sign                   Sign a Card\n\n"

                      "card-unsign                 Unsign the Card\n\n\n"

                      "PUBCLIC KEY COMMANDS:\n"

                      "public-key-revoke           Revoke Public Key\n\n"

                      "public-key-get              Get Public Key\n\n\n"

                      "PRIVATE KEY COMMANDS:\n"

                      "public-key-revoke           Revoke Public Key\n\n"

                      "public-key-get              Get Public Key\n\n\n"

                      "IDENTITY COMMANDS:\n"

                      "identity-verify             Verify a Identity\n\n"

                      "identity-confirm            Confirm the Identity\n\n"

                      "identity-valid              Validate the Identity\n\n\n";

    out << "USAGE: " << programName << " " << doc << std::endl;
}

#endif /* SPLIT_CLI */
