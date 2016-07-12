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

#ifndef VIRGIL_CLI_DESCRIPTION_UTILITIES_COMMON_H
#define VIRGIL_CLI_DESCRIPTION_UTILITIES_COMMON_H

namespace virgil {
namespace cli {

    /* common */
    const char* const kFile_TypeDesc = "file";
    const char* const kArg_TypeDesc = "arg";

    const char* const kGlobalValidatedIdentity_Description =
        "Validated identity (see 'virgil identity-confirm-global')";

    const char* const kPrivateValidatedIdentity_Description =
        "Validated identity (see 'virgil identity-confirm-private')";

    const char* const kValidatedIdentity_ShortName = "f";
    const char* const kValidatedIdentity_LongName = "validated-identity";
    const char* const kValidatedIdentity_TypeDesc = kFile_TypeDesc;

    const char* const kGlobalIdentity_Description =
        "global Identity must required type:email. For example: email:alice@domain.com";

    const char* const kPrivateIdentity_Description = "private Identity <any_type>:<any_value>. For example:\n"
                                                     "phone:+123456789012,\n"
                                                     "<obfuscated_identity>:<obfuscated_value>";

    const char* const kIdentity_ShortName = "d";
    const char* const kIdentity_LongName = "identity";
    const char* const kIdentity_TypedDesc = kArg_TypeDesc;

    /* verbose */
    const char* const kVerbose_Description = "Shows detailed information.";
    const char* const kVerbose_ShortName = "V";
    const char* const kVerbose_LongName = "VERBOSE";
    /* verbose */

    /* private key */
    const char* const kPrivateKey_Description = "Private Key.";
    const char* const kPrivateKey_ShortName = "k";
    const char* const kPrivateKey_LongName = "key";
    const char* const kPrivateKey_TypeDesc = kFile_TypeDesc;
    /* private key */

    /* private key password */
    const char* const kPrivateKeyPassword_Description = "Private Key password.";
    const char* const kPrivateKeyPassword_ShortName = "p";
    const char* const kPrivateKeyPassword_LongName = "private-key-password";
    const char* const kPrivateKeyPassword_TypeDesc = kArg_TypeDesc;
    /* private key password */

    const char* const kPublicKeyId_Description = "Public key identifier.";
    const char* const kPublicKeyId_ShortName = "e";
    const char* const kPublicKeyId_LongName = "public-key-id";
    const char* const kPublicKeyId_TypeDesc = kArg_TypeDesc;

    const char* const kCardId_Description = "Virgil Card identifier.";
    const char* const kCardId_ShortName = "a";
    const char* const kCardId_LongName = "card-id";
    const char* const kCardId_TypeDesc = kArg_TypeDesc;

    /* common */
}
}

#endif /* VIRGIL_CLI_DESCRIPTION_UTILITIES_COMMON_H */
