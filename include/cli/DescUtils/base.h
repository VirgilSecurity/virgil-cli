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

#ifndef VIRGIL_CLI_DESCRIPTION_UTILITIES_BASE_H
#define VIRGIL_CLI_DESCRIPTION_UTILITIES_BASE_H

#include "common.h"

namespace cli {
/* config */
const char* const kConfig_Description = "Get information about Virgil CLI configuration file.";

const char* const kConfig_SwitchGlobal_Description = "Show path to the configuration file applied for all users.";

const char* const kConfig_SwitchLocal_Description = "Show path to the configuration file applied for current user.";

const char* const kConfig_SwitchTemplate_Description = "Show configuration file template.";
/* config */

/**************************************************************/

/* decrypt */
const char* const kDecrypt_Description = "Decrypt data with given password or given Private Key + recipient-id. "
                                         "recipient-id is an identifier which is connected with Public Key. "
                                         "If a sender has a Card, his8 recipient-id is Card's id. Also, Public "
                                         "Key is saved in the Card.";

const char* const kDecrypt_Input_Description = "Data to be decrypted. If omitted, stdin is used.";

const char* const kDecrypt_Output_Description = "Decrypted data. If omitted, stdout is used.";

const char* const kDecrypt_ContentInfo_Description = "Content info. Use this option if"
                                                     " content info is not embedded in the encrypted data.";

const char* const kDecrypt_Recipient_Description =
    "Recipient defined in format:\n"
    "[password|id|vcard|email|private]:<value>\n"
    "where:\n"
    "\t* password:<value> - recipient's password\n"
    "\t* id:<value> - recipient's UUID associated with a Virgil Card identifier\n"
    "\t* vcard:<value> - recipient's Virgil Card/Cards file stored locally\n"
    "\t* email:<value> - recipient's email\n"
    "\t* private:type:value for searching Private Virgil Card(s).\n";
/* decrypt */

/**************************************************************/

// /* encrypt */
const char* const kEncrypt_Description = "The utility allows you to encrypt data with a password or combination "
                                         "of Public Key + recipient-id. recipient-id is an identifier which "
                                         "will be connected with the Public Key. If a sender has a Card, his "
                                         "recipient-id is the Card's id. Also, the Public Keys is saved in  "
                                         "the Card.";

const char* const kEncrypt_Input_Description = "Data to be encrypted. If omitted, stdin is used.";

const char* const kEncrypt_Output_Description = "Encrypted data. If omitted, stdout is used.";

const char* const kEncrypt_ContentInfo_Description = "Content info - meta information about encrypted data. If"
                                                     " omitted, becomes a part of the encrypted data.";

const char* const kEncrypt_UnlabeledRecipient_Description =
    "Contains information about one recipient.\n"
    "Format: [password|id|vcard|email|pubkey|private]:<value>\n"
    "where:\n"
    "\t* password:<value> - recipient's password\n"
    "\t* id:<value> - recipient's UUID associated with Virgil Card\n"
    "\t  identifier\n"
    "\t* vcard:<value> - recipient's the Virgil Card file stored locally\n"
    "\t* email:<value> - recipient's email\n"
    "\t* pubkey:<value> - recipient's public key + identifier,\n"
    "\t  for example: pubkey:bob/public.key:ForBob.\n"
    "\t* private:type:value for searching Private Virgil Card(s)\n";
/* encrypt */

/**************************************************************/

/* exhash */
const char* const kExhash_Descritpion = "Derives hash from the given data with PBKDF function.";

const char* const kExhash_Input_Description = "The string value to be hashed. If omitted, stdout is used.";

const char* const kExhash_Output_Description = "Hash. If omitted, stdout is used.";

const char* const kExhash_Salt_Descritpion = "The hash salt.";

const char* const kExhash_Algorithm_Description = "Underlying hash algorithm:\n"
                                                  "\t* sha1 -   secure Hash Algorithm 1\n"
                                                  "\t* sha224 - secure Hash Algorithm 2, that are 224 bits\n"
                                                  "\t* sha256 - secure Hash Algorithm 2, that are 256 bits\n"
                                                  "\t* sha384 - secure Hash Algorithm 2, that are 384 bits(default)\n"
                                                  "\t* sha512 - secure Hash Algorithm 2, that are 512 bits\n";

const char* const kExhash_Iterations_Description = "Iterations count. Default - 2048";

/* exhash */

/**************************************************************/

/* key2pub */
const char* const kKey2pub_Description = "Extract Public Key from the Private Key.";

const char* const kKey2pub_Input_Description = "Private key. If omitted, stdin is used.";

const char* const kKey2pub_Output_Description = "Public key. If omitted, stdout is used.";
/* key2pub */

/**************************************************************/

/* keygen */
const char* const kKeygen_Description = "Generate Elliptic Curve or RSA Private Key.";

const char* const kKeygen_Output_Description = "Private key. If omitted, stdout is used.";

const char* const kKeygen_Algorithm_Description = "Generate elliptic curve key or RSA key with one"
                                                  " of the following positions:\n"
                                                  "\t* bp256r1 - 256-bits Brainpool curve\n"
                                                  "\t* bp384r1 - 384-bits Brainpool curve\n"
                                                  "\t* bp512r1 - 512-bits Brainpool curve\n"
                                                  "\t* secp192r1 - 192-bits NIST curve\n"
                                                  "\t* secp224r1 - 224-bits NIST curve\n"
                                                  "\t* secp256r1 - 256-bits NIST curve\n"
                                                  "\t* secp384r1 - 384-bits NIST curve\n"
                                                  "\t* secp521r1 - 521-bits NIST curve\n"
                                                  "\t* secp192k1 - 192-bits \"Koblitz\" curve\n"
                                                  "\t* secp224k1 - 224-bits \"Koblitz\" curve\n"
                                                  "\t* secp256k1 - 256-bits \"Koblitz\" curve\n"
                                                  "\t* curve25519 - Curve25519 (default)\n"
                                                  "\t* rsa3072 - 3072-bits \"RSA\" key\n"
                                                  "\t* rsa4096 - 4096-bits \"RSA\" key\n"
                                                  "\t* rsa8192 - 8192-bits \"RSA\" key";

const char* const kKeygen_PrivateKeyPassword_Description = "Password to be used for private key encryption.";

const char* const kKeygen_SwitchNoShadowInput_Description =
    "If parameter -p, --private-key-password is omitted, password won’t be requested.";

/* keygen */

/**************************************************************/

/* sign */
const char* const kSign_Description = "Sign data with given user's Private Key.";

const char* const kSign_Input_Description = "Data to be signed. If omitted, stdin is used.";

const char* const kSign_Output_Description = "Digest sign. If omitted, stdout is used.";

const char* const kSign_PrivateKey_Description = "Signer's Private Key.";
/* sign */

/**************************************************************/

/* verify */
const char* const kVerify_Description = "The utility allows you to verify data and signature"
                                        "  with a provided user's identifier or with his public key.";

const char* const kVerify_Input_Description = "Data to be verified. If omitted, stdin is used.";

const char* const kVerify_Output_Description = "Verification result: success | failure. If omitted, stdout is used.";

const char* const kVerify_SwitchReturnStatus_Description = "Just returns status, ignores '-o, --out'";

const char* const kVerify_SignDigest_Description = "Digest sign.";

const char* const kVerify_Recipient_Description =
    "Recipient defined in format:\n"
    "[id|vcard|pubkey]:<value>\n"
    "where:\n"
    "\t* id:<value> - recipient's UUID associated with a Virgil Card identifier\n"
    "\t* vcard:<value> - recipient's Virgil Card(s) file\n\t  stored locally\n"
    "\t* pubkey:<value> - recipient's public key.\n";
/* verify */
}

#endif /* VIRGIL_CLI_DESCRIPTION_UTILITIES_BASE_H */
