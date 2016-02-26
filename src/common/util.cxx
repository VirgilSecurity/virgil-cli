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

#include <json.hpp>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

#include <cli/config.h>
#include <cli/version.h>
#include <cli/util.h>

using nlohmann::json;

using virgil::crypto::VirgilByteArray;

using virgil::sdk::ServicesHub;
using virgil::sdk::model::Card;
using virgil::sdk::model::Identity;
using virgil::sdk::model::IdentityType;
using virgil::sdk::io::Marshaller;
using virgil::sdk::io::cardsFromJson;

typedef std::pair<std::string, std::string> PairStringString;


void virgil::cli::printVersion(std::ostream& out, const char *programName) {
    out << programName << "  " << "version: "<< virgil::cli_version() << std::endl;
}

//-------------------------------------------------------------------------------------

void virgil::cli::checkFormatRecipientArg(const std::pair<std::string, std::string>& pairRecipientArg) {
    const std::string type = pairRecipientArg.first;
    if (type != "pass" && type != "id" && type != "vcard" && type != "email") {
        throw std::invalid_argument(
                    "invalid type format: " + type + ". Expected format: '<key>:<value>'. "
                                                     "Where <key> = [pass|id|vcard|email]");
    }
}

//-------------------------------------------------------------------------------------

VirgilByteArray virgil::cli::readFileBytes(const std::string& in) {
    std::ifstream inFile(in, std::ios::in | std::ios::binary);
    if (!inFile) {
        throw std::invalid_argument("can not read file: " + in);
    }
    return VirgilByteArray((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
}

VirgilByteArray virgil::cli::readInput(const std::string& in) {
    if(in.empty() || in == "-") {
        return VirgilByteArray((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    }
    return readFileBytes(in);
}

//-------------------------------------------------------------------------------------

void virgil::cli::writeBytes(const std::string& out, const VirgilByteArray& data) {
    if (out.empty()) {
        std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));
        std::cout << std::endl;
        return;
    }

    std::ofstream outFile(out, std::ios::out | std::ios::binary);
    if (!outFile) {
        throw std::invalid_argument("can not write file: " + out);
    }
    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(outFile));
}

void virgil::cli::writeBytes(const std::string& out, const std::string& data) {
    return virgil::cli::writeBytes(out, virgil::crypto::str2bytes(data));
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

std::vector<Card> virgil::cli::getRecipientCards(const std::string& type, const std::string& value,
        const bool includeUnconrimedCard) {

    std::vector<Card> recipientCards;
    ServicesHub servicesHub(VIRGIL_ACCESS_TOKEN);
    if (type == "id") {
        recipientCards.push_back(servicesHub.card().get(value));
    } else if (type == "email") {
        Identity identity(value, IdentityType::Email);
        std::vector<Card> cards;
        if (!includeUnconrimedCard) {
            cards = servicesHub.card().search(identity, std::vector<std::string>(),
                    includeUnconrimedCard);
        } else {
            cards = servicesHub.card().search(identity);
        }
        recipientCards.insert(std::end(recipientCards), std::begin(cards), std::end(cards));
    } else if (type == "vcard") {
        std::string pathTofile = value;
        std::ifstream inFile(pathTofile, std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::invalid_argument("can not read file: " + pathTofile);
        }

        // in file may be card or cards
        std::string undefinedCardJsonStr((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());

        json tmp = json::parse(undefinedCardJsonStr);
        if (tmp.is_object()) {
            Card card = Marshaller<Card>::fromJson(undefinedCardJsonStr);
            recipientCards.push_back(card);
        } else if (tmp.is_array()) {
            std::vector<Card> cards = cardsFromJson(undefinedCardJsonStr);
            recipientCards.insert(std::end(recipientCards), std::begin(cards), std::end(cards));
        } else {
            // exception
        }
    }

    return recipientCards;
}

std::vector<std::string> virgil::cli::getRecipientCardsId(const std::string& type, const std::string& value,
        const bool includeUnconrimedCard) {
    std::vector<Card> recipientCards = virgil::cli::getRecipientCards(type, value, includeUnconrimedCard);
    std::vector<std::string> recipientCardsId;
    for(const auto& recipientCard : recipientCards) {
        recipientCardsId.push_back(recipientCard.getId());
    }
    return recipientCardsId;
}
