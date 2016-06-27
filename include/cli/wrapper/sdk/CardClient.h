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

#ifndef VIRGIL_CLI_WRAPPER_SDK_CARD_CLIENT_H
#define VIRGIL_CLI_WRAPPER_SDK_CARD_CLIENT_H

#include <vector>

#include <virgil/sdk/ServicesHub.h>

namespace virgil_cli {
namespace wrapper {
    namespace sdk {

        class CardClient {
        public:
            CardClient();
            explicit CardClient(const virgil::sdk::ServicesHub& servicesHub);

        public:
            virgil::sdk::models::CardModel getCardById(const std::string& recipientId);
            std::vector<virgil::sdk::models::CardModel> getGlobalCards(const std::string& email);
            std::vector<virgil::sdk::models::CardModel>
            getConfirmedPrivateCards(const std::string& value, const std::string& type = std::string());

        private:
            virgil::sdk::ServicesHub initFromConfigFile();

        private:
            virgil::sdk::ServicesHub servicesHub_;
        };

        virgil::sdk::models::CardModel readCard(const std::string& in);
    }
}
}

#endif /* VIRGIL_CLI_WRAPPER_SDK_CARD_CLIENT_H */
