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

typedef int (*main_func)(int argc, char **argv);

// simple-action
int encrypt_main(int argc, char **argv);
int decrypt_main(int argc, char **argv);
int sign_main(int argc, char **argv);
int verify_main(int argc, char **argv);

// module-action
int public_key_add_main(int argc, char **argv);
int public_key_get_main(int argc, char **argv);
int public_key_del_main(int argc, char **argv);
int public_key_update_main(int argc, char **argv);
int public_key_reset_main(int argc, char **argv);
int public_key_confirm_main(int argc, char **argv);
int public_key_id_get_main(int argc, char **argv);

int user_data_add_main(int argc, char **argv);
int user_data_del_main(int argc, char **argv);
int user_data_confirm_main(int argc, char **argv);
int user_data_reconfirm_main(int argc, char **argv);

int private_key_gen_main(int argc, char **argv);
int private_key_extr_pub_main(int argc, char **argv);
int private_key_add_main(int argc, char **argv);
int private_key_get_main(int argc, char **argv);
int private_key_del_main(int argc, char **argv);

int private_container_auth_main(int argc, char **argv);
int private_container_create_main(int argc, char **argv);
int private_container_del_main(int argc, char **argv);
int private_container_info_main(int argc, char **argv);
int private_container_update_main(int argc, char **argv);
int private_container_reset_pass_main(int argc, char **argv);
int private_container_confirm_main(int argc, char **argv);


static void print_usage(std::ostream &out, const char *programName, const std::string& doc);


int main(int argc, char **argv) {
        // Read doc
    std::string pathToDocFile = "doc.txt";
    std::ifstream docFile(pathToDocFile, std::ios::in | std::ios::binary);
    if (!docFile) {
        throw std::invalid_argument("can not read doc file: " + pathToDocFile);
    }

    std::string docData((std::istreambuf_iterator<char>(docFile)),
                std::istreambuf_iterator<char>());

    // Parse arguments.
    if (argc < 2) {
        std::cerr << "Error: " << " Required argument missing: " << "command" << std::endl;
        print_usage(std::cerr, argv[0], docData);
        return EXIT_FAILURE;
    }

    std::string firstArg(argv[1]);
    if (firstArg == "-h" || firstArg == "--help") {
        print_usage(std::cout, argv[0], docData);
        return EXIT_SUCCESS;
    } else if (firstArg == "--version") {
        virgil::cli::print_version(std::cout, argv[0]);
        return EXIT_SUCCESS;
    }

    std::map<std::string, main_func> commandsMap;
    // simple-action
    commandsMap["encrypt"] = &encrypt_main;
    commandsMap["decrypt"] = &decrypt_main;
    commandsMap["sign"] = &sign_main;
    commandsMap["verify"] = &verify_main;

    // module-action
    commandsMap["public-key-add"] = &public_key_add_main;
    commandsMap["public-key-get"] = &public_key_get_main;
    commandsMap["public-key-del"] = &public_key_del_main;
    commandsMap["public-key-update"] = &public_key_update_main;
    commandsMap["public-key-reset"] = &public_key_reset_main;
    commandsMap["public-key-confirm"] = &public_key_confirm_main;
    commandsMap["public-key-id-get"] = &public_key_id_get_main;
    
    commandsMap["user-data-add"] = &user_data_add_main;
    commandsMap["user-data-del"] = &user_data_del_main;
    commandsMap["user-data-confirm"] = &user_data_confirm_main;
    commandsMap["user-data-reconfirm"] = &user_data_reconfirm_main;

    commandsMap["private-key-gen"] = &private_key_gen_main;
    commandsMap["private-key-extr-pub"] = &private_key_extr_pub_main;
    commandsMap["private-key-add"] = &private_key_add_main;
    commandsMap["private-key-get"] = &private_key_get_main;
    commandsMap["private-key-del"] = &private_key_del_main;

    commandsMap["container-auth"] = &private_container_auth_main;
    commandsMap["container-create"] = &private_container_create_main;
    commandsMap["container-del"] = &private_container_del_main;
    commandsMap["container-info"] = &private_container_info_main;
    commandsMap["container-update"] = &private_container_update_main;
    commandsMap["container-reset"] = &private_container_reset_pass_main;
    commandsMap["container-confirm"] = &private_container_confirm_main;

    auto module = commandsMap.find(firstArg);
    if (module != commandsMap.end()) {
        module->second(argc - 1, argv + 1);
    } else {
        std::cerr << "Error: " << "command '" << firstArg << "' not found" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void print_usage(std::ostream &out, const char *programName, const std::string& doc) {
    out << "USAGE:"  <<  programName << doc << std::endl;
}

#endif /* SPLIT_CLI */
