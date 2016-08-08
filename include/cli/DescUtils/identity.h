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

#ifndef VIRGIL_CLI_DESCRIPTION_UTILITIES_IDENTITY_H
#define VIRGIL_CLI_DESCRIPTION_UTILITIES_IDENTITY_H

namespace cli {
/* identity-confirm-global */
const char* const kIdentityConfirmGlobal_Description = "Confirm identity for a Global Virgil Card";
/* identity-confirm-global */

/**************************************************************/

/* identity-confirm-private */
const char* const kIdentityConfirmPrivate_Description =
    "Provides helper methods to generate validation token based on the"
    "application's private key. It is required for the following"
    "operations:\n"
    "1. Create a private Virgil Card with a confirmed Identity. "
    "See 'virgil card-create-private'\n"
    "2. Revoke a Private Virgil Card, a group of Cards. "
    "See 'virgil card-revoke-private', 'virgil public-key-revoke'\n"
    "3. Get a private key from the Private Keys Service. "
    "See 'virgil private-key-get'.\n\n";
/* identity-confirm-private */

/**************************************************************/

/* identity-valid */
const char* const kIdentityValid_Description = "Check 'validated-identity' received by 'identity-confirm-global'";
/* identity-valid */

/**************************************************************/

/* identity-verify */
const char* const kIdentityVerify_Description = "Verify an Identity for Global Virgil Card.\n"
                                                "1. Send 'confirmation_code' on the email"
                                                "2. Return 'action_id'.";
/* identity-verify */
}

#endif /* VIRGIL_CLI_DESCRIPTION_UTILITIES_IDENTITY_H */
