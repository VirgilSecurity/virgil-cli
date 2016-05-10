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

#include <algorithm>
#include <iostream>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>

#if defined(WIN32)
#include <cfgpath.h>
#include <Windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilKeyPair.h>

#include <json.hpp>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/models/PrivateKeyModel.h>

#include <cli/ini.hpp>
#include <cli/pair.h>
#include <cli/version.h>
#include <cli/util.h>

using json = nlohmann::json;

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

typedef std::pair<std::string, std::string> PairStringString;

static void setStdinEcho(bool enable) {
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    if (!enable) {
        mode &= ~ENABLE_ECHO_INPUT;
    } else {
        mode |= ENABLE_ECHO_INPUT;
    }
    SetConsoleMode(hStdin, mode);

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }

    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

virgil::cli::ConfigFile virgil::cli::readConfigFile(const bool verbose) {
    std::string pathConfigFile;
#if defined(WIN32)
    char cfgdir[MAX_PATH];
    get_user_config_folder(cfgdir, sizeof(cfgdir), "virgil-cli");
    if (cfgdir[0] == 0) {
        if (verbose) {
            std::cout << "Can't find config file";
        }
        return ConfigFile();
    } else {
        if (verbose) {
            std::cout << "File found by path:" << std::string(cfgdir) << std::endl;
        }
    }

    pathConfigFile = std::string(cfgdir);
    pathConfigFile += "\\virgil-cli-config.ini";
#else
    pathConfigFile = INSTALL_CONFIG_FILE_DIR + "/virgil-cli-config.ini";
#endif

    std::ifstream inFile(pathConfigFile, std::ios::in | std::ios::binary);
    if (!inFile) {
        if (verbose) {
            std::cout << "Can't read config file:\n" + pathConfigFile << std::endl;
        }
        return ConfigFile();
    }

    try {
        std::string ini((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        std::stringstream ss(ini);
        INI::Parser iniParser(ss);

        ConfigFile configFile;
        configFile.virgilAccessToken = iniParser.top()("Virgil Access Token")["token"];
        if (configFile.virgilAccessToken.empty()) {
            configFile.virgilAccessToken = VIRGIL_ACCESS_TOKEN;
        }

        configFile.serviceUri =
            vsdk::ServiceUri(iniParser.top()("URI")["identity-service"], iniParser.top()("URI")["public-key-service"],
                             iniParser.top()("URI")["private-key-service"]);

        if (verbose) {
            std::cout << "Virgil Access Token:\n" << configFile.virgilAccessToken << "\n\n";
            std::cout << "Identity Service:\n" << configFile.serviceUri.getIdentityService() << "\n\n";
            std::cout << "Public Key Service:\n" << configFile.serviceUri.getPublicKeyService() << "\n\n";
            std::cout << "Private Key Service:\n" << configFile.serviceUri.getPrivateKeyService() << "\n\n";
        }

        return configFile;

    } catch (std::runtime_error& exception) {
        std::string error = "Can't parse config file " + pathConfigFile + ".\n";
        error += exception.what();
        throw std::runtime_error(error);
    }
}

std::string virgil::cli::inputShadow() {
    setStdinEcho(false);
    std::string str;
    std::cin >> std::ws;
    std::cin >> str;
    setStdinEcho(true);
    return str;
}

vcrypto::VirgilByteArray virgil::cli::setPrivateKeyPass(const vcrypto::VirgilByteArray& privateKey) {
    if (vcrypto::VirgilKeyPair::isPrivateKeyEncrypted(privateKey)) {
        std::string privateKeyPass;
        std::cout << "Enter private key password:" << std::endl;
        privateKeyPass = inputShadow();
        vcrypto::VirgilByteArray privateKeyPassByteArray = vcrypto::str2bytes(privateKeyPass);
        if (vcrypto::VirgilKeyPair::checkPrivateKeyPassword(privateKey, privateKeyPassByteArray)) {
            return privateKeyPassByteArray;
        } else {
            throw std::runtime_error("private key pass is invalid");
        }
    }
    return vcrypto::VirgilByteArray();
}

bool virgil::cli::isPublicKeyModel(const std::string& publicKey) {
    std::istringstream iss(publicKey);
    std::string firstLine;
    std::getline(iss, firstLine);
    try {
        json tmp = json::parse(publicKey);
        return tmp.is_object() && tmp.find("id") != tmp.end() && tmp.find("public_key") != tmp.end() &&
               tmp.find("created_at") != tmp.end();
    } catch (std::exception&) {
        return false;
    }
}

bool virgil::cli::isPrivateKeyModel(const std::string& privateKey) {
    std::istringstream iss(privateKey);
    std::string firstLine;
    std::getline(iss, firstLine);
    try {
        json tmp = json::parse(privateKey);
        return tmp.is_object() && tmp.find("private_key") != tmp.end() && tmp.find("virgil_card_id") != tmp.end();
    } catch (std::exception&) {
        return false;
    }
}

void virgil::cli::printVersion(std::ostream& out, const char* programName) {
    out << programName << "  "
        << "version: " << virgil::cli_version() << std::endl;
}

//-------------------------------------------------------------------------------------

void virgil::cli::checkFormatRecipientArg(const std::pair<std::string, std::string>& pairRecipientArg) {
    const std::string type = pairRecipientArg.first;
    if (type != "password" && type != "id" && type != "vcard" && type != "email" && type != "pubkey" &&
        type != "private") {
        throw std::invalid_argument("invalid type format: " + type +
                                    ". Expected format: '<key>:<value>'. "
                                    "Where <key> = [password|id|vcard|email|pubkey|private]");
    }
}

void virgil::cli::checkFormatIdentity(const std::string& args, const std::string& type) {
    if (type != "email") {
        throw std::invalid_argument(args + " invalid type format: " + type + ". Expected format: '<key>:<value>'. "
                                                                             "Where <key> = [email].");
    }
}

//-------------------------------------------------------------------------------------

vcrypto::VirgilByteArray virgil::cli::readFileBytes(const std::string& in) {
    std::ifstream inFile(in, std::ios::in | std::ios::binary);
    if (!inFile) {
        throw std::invalid_argument("can not read file: " + in);
    }
    return vcrypto::VirgilByteArray((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
}

std::string virgil::cli::readInput(const std::string& in) {
    if (in.empty() || in == "-") {
        return std::string((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    } else {
        std::ifstream inFile(in, std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::invalid_argument("can not read file: " + in);
        }
        return std::string((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    }
}

vsdk::dto::ValidatedIdentity virgil::cli::readValidateIdentity(const std::string& in) {
    std::ifstream inFile(in, std::ios::in | std::ios::binary);
    if (!inFile) {
        throw std::invalid_argument("cannot read file: " + in);
    }
    std::string validatedIdentityStr((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    return vsdk::io::Marshaller<vsdk::dto::ValidatedIdentity>::fromJson(validatedIdentityStr);
}

vsdk::models::CardModel virgil::cli::readCard(const std::string& in) {
    std::ifstream inFile(in, std::ios::in | std::ios::binary);
    if (!inFile) {
        throw std::invalid_argument("cannot read file: " + in);
    }
    std::string cardStr((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    return vsdk::io::Marshaller<vsdk::models::CardModel>::fromJson(cardStr);
}

virgil::crypto::VirgilByteArray virgil::cli::readPublicKey(const std::string& in) {
    vcrypto::VirgilByteArray publicKey;
    std::string pathToPublicKeyFile = in;
    std::ifstream inFile(pathToPublicKeyFile, std::ios::in | std::ios::binary);
    if (!inFile) {
        throw std::invalid_argument("cannot read file: " + pathToPublicKeyFile);
    }
    std::string publicKeyStr((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());

    if (virgil::cli::isPublicKeyModel(publicKeyStr)) {
        vsdk::models::PublicKeyModel publicKeyModel =
            vsdk::io::Marshaller<vsdk::models::PublicKeyModel>::fromJson(publicKeyStr);
        publicKey = publicKeyModel.getKey();
    } else {
        publicKey = vcrypto::str2bytes(publicKeyStr);
    }
    return publicKey;
}

virgil::crypto::VirgilByteArray virgil::cli::readPrivateKey(const std::string& in) {
    vcrypto::VirgilByteArray privateKey;
    std::string pathToPrivateKeyFile = in;
    std::ifstream inFile(pathToPrivateKeyFile, std::ios::in | std::ios::binary);
    if (!inFile) {
        throw std::invalid_argument("cannot read file: " + pathToPrivateKeyFile);
    }
    std::string privateKeyStr((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    if (virgil::cli::isPrivateKeyModel(privateKeyStr)) {
        vsdk::models::PrivateKeyModel privateKeyModel =
            vsdk::io::Marshaller<vsdk::models::PrivateKeyModel>::fromJson(privateKeyStr);
        privateKey = privateKeyModel.getKey();
    } else {
        privateKey = vcrypto::str2bytes(privateKeyStr);
    }
    return privateKey;
}

//-------------------------------------------------------------------------------------

void virgil::cli::writeBytes(const std::string& out, const vcrypto::VirgilByteArray& data) {
    if (out.empty()) {
        std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));
        std::cout << std::endl;
        return;
    }

    std::ofstream outFile(out, std::ios::out | std::ios::binary);
    if (!outFile) {
        throw std::invalid_argument("cannot write file: " + out);
    }
    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(outFile));
}

void virgil::cli::writeBytes(const std::string& out, const std::string& data) {
    return virgil::cli::writeBytes(out, virgil::crypto::str2bytes(data));
}

void virgil::cli::writeOutput(const std::string& out, const std::string& data) {
    if (out.empty()) {
        std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));
        std::cout << std::endl;
        return;
    }

    std::ofstream outFile(out, std::ios::out | std::ios::binary);
    if (!outFile) {
        throw std::invalid_argument("cannot write file: " + out);
    }
    outFile << data;
}

//-------------------------------------------------------------------------------------

std::string virgil::cli::getDescriptionMessage(const std::string description, std::vector<std::string> examples) {
    std::string descriptionMessage;
    descriptionMessage += "\nDESCRIPTION:\n" + description;
    if (!examples.empty()) {
        descriptionMessage += "EXAMPLES:\n";
        for (const auto& example : examples) {
            descriptionMessage += example;
        }
    }
    return descriptionMessage;
}

//-------------------------------------------------------------------------------------

std::vector<vsdk::models::CardModel> virgil::cli::getRecipientCards(const bool verbose, const std::string& type,
                                                                    const std::string& value,
                                                                    const bool isSearchForPrivateCard) {
    std::vector<vsdk::models::CardModel> recipientCards;
    ConfigFile configFile = readConfigFile(verbose);
    vsdk::ServicesHub servicesHub(configFile.virgilAccessToken, configFile.serviceUri);

    if (isSearchForPrivateCard) {
        std::vector<vsdk::models::CardModel> cards;
        if (verbose) {
            std::cout << "Searching the Private Virgil Card[s] with confirmed identity by type:" << type
                      << " value:" << value << std::endl;
        }
        cards = servicesHub.card().search(value, type);
        if (!cards.empty()) {
            recipientCards.insert(std::end(recipientCards), std::begin(cards), std::end(cards));
            if (verbose) {
                std::cout << "For the entered type:" << type << "  value:" << value << "have been received "
                          << cards.size() << " Virgil Card[s]." << std::endl;
            }
        } else {
            throw std::invalid_argument(std::string("Private Virgil Cards by type: ") + type + " value:" + value +
                                        " haven't been found.");
        }
    }

    if (type == "id") {
        auto card = servicesHub.card().get(value);
        recipientCards.push_back(card);
        if (verbose) {
            std::cout << "For the entered id: " << value << " have been received a Virgil Card." << std::endl;
        }
    } else if (type == "email" && !isSearchForPrivateCard) {
        std::vector<vsdk::models::CardModel> cards;
        if (verbose) {
            std::cout << "Searching the Global Virgil Card[s] by type:" << type << " value:" << value << std::endl;
        }
        cards = servicesHub.card().searchGlobal(value, vsdk::dto::IdentityType::Email);
        if (!cards.empty()) {
            recipientCards.insert(std::end(recipientCards), std::begin(cards), std::end(cards));
            if (verbose) {
                std::cout << "For the entered type:" << type << "  value:" << value << "have been received "
                          << cards.size() << " Virgil Card[s]." << std::endl;
            }
        } else {
            throw std::invalid_argument(std::string("Global Virgil Cards by email: ") + value + " haven't been found.");
        }
    } else if (type == "vcard") {
        std::string pathTofile = value;
        std::ifstream inFile(pathTofile, std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::invalid_argument("cannot read file: " + pathTofile);
        }
        std::string jsonCard((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        vsdk::models::CardModel card = vsdk::io::Marshaller<vsdk::models::CardModel>::fromJson(jsonCard);
        if (verbose) {
            std::cout << "A Virgil Card by path " << pathTofile << " read." << std::endl;
        }
        recipientCards.push_back(card);
    }

    return recipientCards;
}

std::vector<std::string> virgil::cli::getRecipientCardsId(const bool verbose, const std::string& type,
                                                          const std::string& value, const bool isSearchForPrivateCard) {
    std::vector<vsdk::models::CardModel> recipientCards =
        virgil::cli::getRecipientCards(verbose, type, value, isSearchForPrivateCard);
    std::vector<std::string> recipientCardsId;
    for (const auto& recipientCard : recipientCards) {
        recipientCardsId.push_back(recipientCard.getId());
    }
    return recipientCardsId;
}
