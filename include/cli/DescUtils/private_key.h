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

#ifndef VIRGIL_CLI_DESCRIPTION_UTILITIES_PRIVATE_KEY_H
#define VIRGIL_CLI_DESCRIPTION_UTILITIES_PRIVATE_KEY_H

namespace cli {
/* private-key-add */
const char* const kPrivateKeyAdd_Description =
    "Add given Private Key into the Private Keys Service.\n"
    "General statements:\n"
    "1. Make sure that you have registered and confirmed your account for the Public Keys Service\n"
    "2. Make sure that you have a public/private key pair and you have already uploaded the public key\n"
    "to the Public Keys Service\n"
    "3. Make sure that you have your private key saved locally\n"
    "4. Make sure that you have registered an application at Virgil Security, Inc.";
/* private-key-add */

/**************************************************************/

/* private-key-del */
const char* const kPrivateKeyDel_Description = "Delete a Private key from the Private Key Service";
/* private-key-del */

/**************************************************************/

/* private-key-get */
const char* const kPrivateKeyGet_Description = "Get a Private key from the Private Key Service";
/* private-key-get */
}

#endif /* VIRGIL_CLI_DESCRIPTION_UTILITIES_PRIVATE_KEY_H */
