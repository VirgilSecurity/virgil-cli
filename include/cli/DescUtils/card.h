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

#ifndef VIRGIL_CLI_DESCRIPTION_UTILITIES_CARD_H
#define VIRGIL_CLI_DESCRIPTION_UTILITIES_CARD_H

namespace cli {
/* card-create-global */
const char* const kCardCreateGlobal_Description = "Create a Global Virgil Card.";

const char* const kCardCreateGlobal_Output_Description = "Global Virgil Card. If omitted, stdout is used.";

const char* const kCardCreateGlobal_ValidatedIdentity_Description =
    "Validated identity (see 'virgil identity-confirm-global')";

const char* const kCardCreateGlobal_Identity_Description = "Identity: email:value";

const char* const kCardCreateGlobal_PublicKey_Description = "Public key";
/* card-create-global */

/* card-create-private */
const char* const kCardCreatePrivate_Description = "Create a Private Virgil Card.";

const char* const kCardCreatePrivate_Output_Description = "Private Virgil Card. If omitted, stdout is used.";

const char* const kCardCreatePrivate_ValidatedIdentity_Description =
    "Validated identity (see 'virgil identity-confirm-private')";

const char* const kCardCreatePrivate_Identity_Description = "Identity: type:value";

const char* const kCardCreatePrivate_PublicKey_Description = "Public key";

const char* const kCardCreatePrivate_PublicKeyId_Description = "Public key identifier";
/* card-create-private */

/* card-get */
const char* const kCardGet_Description = "Return a Private/Global Virgil Card by card-id or a group of "
                                         "Private/Global Cards connected with public-key-id";

const char* const kCardGet_Output_Description = "Folder where Virgil Cards will be saved.";
/* card-get */

/* card-revoke-global */
const char* const kCardRevokeGlobal_Description = "Revoke a Global Virgil Card from the Virgil Public Key service.";

const char* const kCardRevokeGlobal_ValidatedIdentity_Description =
    "Validated identity (see 'virgil identity-confirm-global')";
/* card-revoke-global */

/* card-revoke-private */
const char* const kCardRevokePrivate_Description =
    "Revoke a Private Virgil Card from the Virgil Public Key service.";
/* card-revoke-private */

/* card-search-global */
const char* const kCardSearchGlobal_Description = "Search for a Global Virgil Card from the Virgil Keys Service by:\n"
                                                  "1. application_name - search an application Virgil Global Card\n"
                                                  "2. email - search a Virgil Global Card\n\n";

/* card-search-global */

/* card-search-private */
const char* const kCardSearchPrivate_Description =
    "Search for the Private Virgil Card(s) from the Virgil Keys Service";

const char* const kCardSearchPrivate_Output_Description = "Folder where Virgil Cards will be saved.";

const char* const kCardSearchPrivate_IdentityType_Description =
    "Identity value or obfuscated identity value (see 'virgil hash')";

const char* const kCardSearchPrivate_UnconfirmedIdentity_Description =
    "Includes unconfirmed identities into Cards search.";

/* card-search-private */
}

#endif /* VIRGIL_CLI_DESCRIPTION_UTILITIES_CARD_H */
