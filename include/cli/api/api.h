/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AS IS AND ANY EXPRESS OR
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

#ifndef VIRGIL_CLI_CPP11_API_H
#define VIRGIL_CLI_CPP11_API_H

namespace cli { namespace usage {

static constexpr char VIRGIL[] = R"(
virgil - command line tool for using Virgil Security stack functionality

USAGE:
    virgil <command> [options] [<args>...]

OPTIONS:
    <command>
        Specific command to execute, see sections below.
    <args>
        Options and arguments fot the target command.

COMMON OPTIONS:
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity
    --v=<verbose-level>  
        Activates verbosity with given level (valid range: 1-9)
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.

COMMANDS:
    This section contains brief description of the available commands that are available via Virgil CLI.
    CRYPTO COMMANDS
    keygen
        Generate a Private Key with provided parameters.
    key2pub
        Extract a Public Key from the Private Key.
    encrypt
        Encrypt the data for given recipients who can be defined by their Public Keys and by the passwords (Recipient-id).
    decrypt
        Decrypt the data for a given recipient who can be defined by his Public Key or by the password.
    sign
        Sign the data with the Private Key.
    verify
        Verify the data and the signature with the Public Key.
    exhash
        Derive Hash from the given data with the PBKDF function.
    config
        Get the information about Virgil CLI configuration file.
    VIRGIL CARD SERVICE COMMANDS
    card-create
        Create a Virgil Card entity.
    card-get
        Get the Virgil Card from the Virgil Keys Service by the Virgil Card id.
    card-search
        Search for the Virgil Card from the Virgil Keys Service by the identity.
    card-revoke
        Revoke the Virgil Card by the Virgil Card id.

CONFIGURATION VALUES:
        * APP_ACCESS_TOKEN - is a unique string value that provides an authenticated secure access to the Virgil services.
        * APP_KEY_ID - is a unique string value that identifies your application in our services.
        * APP_KEY_DATA - is a Private key that is used to perform creation and revocation of Virgil Cards (Public key) in the Virgil services.
        * APP_KEY_PASSWORD - password to the APP_KEY_DATA.
)";

static constexpr char VIRGIL_CARD_CREATE[] = R"(
virgil-card-create - creates a Virgil Card entity

USAGE:
    virgil card-create [options...] [-o <file>] -k <file> [-p <arg>] [-s <scope>] [--data <key-value>...] [--info <key-value>...] <identity>

OPTIONS:
    -o <file>, --out=<file>  
        The Virgil Card. If omitted, stdout is used.
    -k <file>, --private-key=<file>  
        Private Key.
    -p <arg>, --private-key-password=<arg>  
        The Private Key password (if exists).
    -s <scope>, --scope=<scope>  
        Determines a Virgil Card scope that can be either global or application [default: application].
            * for global Virgil Card the scope must be global;
            * for application Virgil Card the scope must be application;
        If omitted, application is used.
    --data=<key-value>  
        The data contains application specific parameters. Format: <key>:<value> (up to 16 positions).
    --info=<key-value>  
        The info contains the information about the device on which the keypair was created.
        Format: <key>:<value> (2 positions must be used).
            * the first key must be device_name with any value;
            * the second key must be device with any value.
    <identity>
        Identity that will be associated with created Virgil Card.
        Format: <type>:<value>
            * for confirmed Virgil Card identity type must be email and identity value must be a valid email;
            * for segregated Virgil Card the identity type and value can be any value.
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.

CONFIGURATION VALUES:
        * APP_KEY_ID - is a unique string value that identifies your application in our services.
        * APP_KEY_DATA - is a Private key that is used to perform creation and revocation of Virgil Cards (Public key) in the Virgil services.
        * APP_KEY_PASSWORD - password to the APP_KEY_DATA.
)";

static constexpr char VIRGIL_CARD_GET[] = R"(
virgil-card-get - return the Virgil Card from the Virgil Keys Service by the Virgil Card id.

USAGE:
    virgil card-get [options...] [-i <arg>] [-o <file>]

OPTIONS:
    -i <arg>, --in=<arg>  
        Virgil Card id. If omitted, stdin is used.
    -o <file>, --out=<file>  
        A folder where Virgil Cards will be saved. If omitted, stdout is used.
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";

static constexpr char VIRGIL_CARD_REVOKE[] = R"(
virgil-card-revoke - revokes a Virgil Card directly or by the Virgil Card id

USAGE:
    virgil card-revoke [options...] [-i <file>] [-r <reason>]

OPTIONS:
    -i <file>, --in=<file>  
        The Virgil Card id or the Virgil Card itself for revocation. If omitted, stdin is used.
    -r <reason>, --revocation-reason=<reason>  
        The revocation reason must be unspecified or compromised [default: unspecified].
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";

static constexpr char VIRGIL_CARD_SEARCH[] = R"(
virgil-card-search - searches for a Virgil Card(s) by its identities (required), identity-type and scope.

USAGE:
    virgil card-search [options...] [-o <arg>] [-s <scope>] <identity>...

OPTIONS:
    -o <file>, --out=<file>  
        A folder where Virgil Cards will be saved. If omitted, stdout is used.
    -s <scope>, --scope=<scope>  
        Specifies the scope to perform search on [default: application].
            * for global Virgil Card the scope must be global;
            * for application Virgil Card the scope must be application.
        If omitted, application is used.
    <identity>
        Identity to be found.
        Multiple identitites can be used for the Virgil Cards search.
        Format: <type>:<value>
            * for confirmed Virgil Card identity type must be email and identity value must be a valid email;
            * for segregated Virgil Card the identity type and value can be any value.
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";

static constexpr char VIRGIL_DECRYPT[] = R"(
virgil-decrypt - decrypts the encrypted data

USAGE:
    virgil decrypt [options...] [-i <file>] [-o <file>] [-c <file>] [-p <arg>] <keypass>...

OPTIONS:
    -i <file>, --in=<file>  
        Data to be decrypted. If omitted, stdin is used.
    -o <file>, --out=<file>  
        Decrypted data. If omitted, stdout is used.
    -c <file>, --content-info=<file>  
        Content info. Use this option if content info is not embedded in the encrypted data.
    -p <arg>, --private-key-password=<arg>  
        Private Key Password.
    <keypass>
        Contains Private Key or password. Format: (privkey|password):<value>[:<alias>]
            * if privkey then:
                  + <value> - recipient's Private Key,
                  + <alias> - Private Key alias;
            * if password then:
                  + <value> - recipient's password,
                  + <alias> - ignored.
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";

static constexpr char VIRGIL_ENCRYPT[] = R"(
virgil-encrypt - encrypts any data for the specified recipient(s)

USAGE:
    virgil encrypt [options...] [-i <file>] [-o <file>] [-c <file>] [--] <recipient-id>...

OPTIONS:
    -i <file>, --in=<file>  
        Data to be encrypted. If omitted, stdin is used.
    -o <file>, --out=<file>  
        Encrypted data. If omitted, stdout is used.
    -c <file>, --content-info=<file>  
        Content info <Content info> - meta information about the encrypted data. If omitted, becomes a part of the encrypted data.
    <recipient-id>
        Contains information about one recipient. Format: [password|email|vcard|pubkey]:<value>
            * if password, then <value> - a password for encrypting;
            * if email, then <value> - the email of the recipient;
            * if vcard, then <value> - the recipient's Virgil Card id or the Virgil Card itself (the file stored locally);
            * if pubkey, then <value> - Public Key of the recipient. An alias may also be added. Example: pubkey:bob/public.key:ForBob
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";

static constexpr char VIRGIL_EXHASH[] = R"(
virgil-exhash - derives the obfuscated data from incoming parameters

USAGE:
    virgil exhash [options...] [-i <file>] [-o <file>] -z <file> [-g <alg>] [-x <int>]

OPTIONS:
    -i <file>, --in=<file>  
        The string value to be hashed. If omitted, stdout is used.
    -o <file>, --out=<file>  
        Hash. If omitted, stdout is used.
    -z <file>, --salt=<file>  
        The hash salt.
    -g <alg>, --algorithm=<alg>  
        The underlying hash algorithm [default: sha384]:
            * sha1 - secure Hash Algorithm 1;
            * sha224 - secure Hash Algorithm 2, that are 224 bits;
            * sha256 - secure Hash Algorithm 2, that are 256 bits;
            * sha384 - secure Hash Algorithm 2, that are 384 bits;
            * sha512 - secure Hash Algorithm 2, that are 512 bits;
    -x <int>, --iterations=<int>  
        Iterations count [default: 4096].
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";

static constexpr char VIRGIL_GLOSSARY[] = R"(
virgil-glossary - shows the list of Virgil Services terms

USAGE:
    virgil glossary [options...] [-o <file>]

OPTIONS:
    -o <file>, --out=<file>  
        The list of glossary terms. If omitted, stdout is used.
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";

static constexpr char VIRGIL_KEY2PUB[] = R"(
virgil-key2pub - extracts the Public Key from the Private Key

USAGE:
    virgil key2pub [options...] [-i <file>] [-o <file>] [-p <arg>]

OPTIONS:
    -i <file>, --in=<file>  
        Private key. If omitted, stdin is used.
    -o <file>, --out=<file>  
        Public key. If omitted, stdout is used.
    -p <arg>, --private-key-password=<arg>  
        Private Key Password.
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";

static constexpr char VIRGIL_KEYGEN[] = R"(
virgil-keygen - generate private key with given algorithm

USAGE:
    virgil keygen [options...] [-o <file>] [-g <alg>] [-p <arg> | --no-password]

OPTIONS:
    -o <file>, --out=<file>  
        The generated Private Key. If omitted, stdout is used.
    -g <alg>, --algorithm=<alg>  
        Generate an Elliptic Curve key or an RSA key with one of the following algorithms [default: ed25519]:
            * bp256r1 - 256-bits Brainpool curve;
            * bp384r1 - 384-bits Brainpool curve;
            * bp512r1 - 512-bits Brainpool curve;
            * secp192r1 - 192-bits NIST curve;
            * secp224r1 - 224-bits NIST curve;
            * secp256r1 - 256-bits NIST curve;
            * secp384r1 - 384-bits NIST curve;
            * secp521r1 - 521-bits NIST curve;
            * secp192k1 - 192-bits "Koblitz" curve;
            * secp224k1 - 224-bits "Koblitz" curve;
            * secp256k1 - 256-bits "Koblitz" curve;
            * rsa3072 - 3072-bits "RSA" key;
            * rsa4096 - 4096-bits "RSA" key;
            * rsa8192 - 8192-bits "RSA" key.
            * ed25519 - Ed25519;
    -p <arg>, --private-key-password=<arg>  
        Password to be used for private key encryption.
    --no-password  
        Keep private key without any encryption (not recommended).
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";

static constexpr char VIRGIL_SIGN[] = R"(
virgil-sign - signs data with a provided user's Private Key

USAGE:
    virgil sign [options...] [-i <file>] [-o <file>] -k <file> [-p <arg>] [--hash-algorithm <hash-alg>]

OPTIONS:
    -i <file>, --in=<file>  
        Data to be signed. If omitted, stdin is used.
    -o <file>, --out=<file>  
        Digest sign. If omitted, stdout is used.
    -k <file>, --private-key=<file>  
        Signer's Private Key.
    -p <arg>, --private-key-password=<arg>  
        Private Key password.
    --hash-algorithm=<hash-alg>  
        The underlying hash algorithm [default: sha384]:
            * sha1 - secure Hash Algorithm 1;
            * sha224 - secure Hash Algorithm 2, that are 224 bits;
            * sha256 - secure Hash Algorithm 2, that are 256 bits;
            * sha384 - secure Hash Algorithm 2, that are 384 bits;
            * sha512 - secure Hash Algorithm 2, that are 512 bits.
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";

static constexpr char VIRGIL_VERIFY[] = R"(
virgil-verify - verifies data and signature with a provided user's Public Key or Virgil Card

USAGE:
    virgil verify [options...] [-i <file>] -S <file> <recipient-id>

OPTIONS:
    -i <file>, --in=<file>  
        Data to be signed. If omitted, stdin is used.
    -S <file>, --sign=<file>  
        Digest sign.
    <recipient-id>
        Contains information about the sender. Format: [vcard | pubkey]:<value>
            * if vcard, then <value> - the sender's Virgil Card id or the Virgil Card itself (the file stored locally);
            * if pubkey, then <value> - Public Key of the recipient.
    -h, --help  
        Displays usage information and exits.
    --version  
        Displays version information and exits.
    -v, --verbose  
        Activates maximum verbosity.
    --v=<verbose-level>  
        Activates verbosity upto given verbose level (valid range: 1-9).
    -q, --quiet  
        Quiet mode: suppress normal output.
    -I, --interactive  
        Enables interactive mode.
    -D <config>  
        Rewrite value from the configuration file, i.e. -D APP_ACCESS_TOKEN=AT.KJHjdskhFDJkshfd=
    --  
        Ignores the rest of the labeled arguments following this flag.
)";


}} // cli::usage

namespace cli { namespace opt {

static constexpr char ALGORITHM[] = "--algorithm";
static constexpr char CONTENT_INFO[] = "--content-info";
static constexpr char DATA[] = "--data";
static constexpr char D_SHORT[] = "-D";
static constexpr char HASH_ALGORITHM[] = "--hash-algorithm";
static constexpr char HELP[] = "--help";
static constexpr char IN[] = "--in";
static constexpr char INFO[] = "--info";
static constexpr char INTERACTIVE[] = "--interactive";
static constexpr char ITERATIONS[] = "--iterations";
static constexpr char NO_PASSWORD[] = "--no-password";
static constexpr char OPTIONS_FIRST[] = "--";
static constexpr char OUT[] = "--out";
static constexpr char PRIVATE_KEY[] = "--private-key";
static constexpr char PRIVATE_KEY_PASSWORD[] = "--private-key-password";
static constexpr char QUIET[] = "--quiet";
static constexpr char REVOCATION_REASON[] = "--revocation-reason";
static constexpr char SALT[] = "--salt";
static constexpr char SCOPE[] = "--scope";
static constexpr char SIGN[] = "--sign";
static constexpr char V[] = "--v";
static constexpr char VERBOSE[] = "--verbose";
static constexpr char VERSION[] = "--version";

}} // cli::opt

namespace cli { namespace arg {

static constexpr char ARGS[] = "<args>";
static constexpr char COMMAND[] = "<command>";
static constexpr char IDENTITY[] = "<identity>";
static constexpr char KEYPASS[] = "<keypass>";
static constexpr char RECIPIENT_ID[] = "<recipient-id>";

}} // cli::arg

namespace cli { namespace arg { namespace value {

static constexpr char VIRGIL_CARD_CREATE_IDENTITY_EMAIL[] = "email";
static const char* VIRGIL_CARD_CREATE_IDENTITY_VALUES[] = {
    VIRGIL_CARD_CREATE_IDENTITY_EMAIL,
    nullptr
};

static constexpr char VIRGIL_CARD_CREATE_INFO_KEY_DEVICE[] = "device";
static constexpr char VIRGIL_CARD_CREATE_INFO_KEY_DEVICE_NAME[] = "device_name";
static const char* VIRGIL_CARD_CREATE_INFO_KEY_VALUES[] = {
    VIRGIL_CARD_CREATE_INFO_KEY_DEVICE,
    VIRGIL_CARD_CREATE_INFO_KEY_DEVICE_NAME,
    nullptr
};

static constexpr char VIRGIL_CARD_CREATE_SCOPE_APPLICATION[] = "application";
static constexpr char VIRGIL_CARD_CREATE_SCOPE_GLOBAL[] = "global";
static const char* VIRGIL_CARD_CREATE_SCOPE_VALUES[] = {
    VIRGIL_CARD_CREATE_SCOPE_APPLICATION,
    VIRGIL_CARD_CREATE_SCOPE_GLOBAL,
    nullptr
};

static constexpr char VIRGIL_CARD_REVOKE_REASON_COMPROMISED[] = "compromised";
static constexpr char VIRGIL_CARD_REVOKE_REASON_UNSPECIFIED[] = "unspecified";
static const char* VIRGIL_CARD_REVOKE_REASON_VALUES[] = {
    VIRGIL_CARD_REVOKE_REASON_COMPROMISED,
    VIRGIL_CARD_REVOKE_REASON_UNSPECIFIED,
    nullptr
};

static constexpr char VIRGIL_CARD_SEARCH_IDENTITY_EMAIL[] = "email";
static const char* VIRGIL_CARD_SEARCH_IDENTITY_VALUES[] = {
    VIRGIL_CARD_SEARCH_IDENTITY_EMAIL,
    nullptr
};

static constexpr char VIRGIL_CARD_SEARCH_SCOPE_APPLICATION[] = "application";
static constexpr char VIRGIL_CARD_SEARCH_SCOPE_GLOBAL[] = "global";
static const char* VIRGIL_CARD_SEARCH_SCOPE_VALUES[] = {
    VIRGIL_CARD_SEARCH_SCOPE_APPLICATION,
    VIRGIL_CARD_SEARCH_SCOPE_GLOBAL,
    nullptr
};

static constexpr char VIRGIL_COMMAND_CARD_CREATE[] = "card-create";
static constexpr char VIRGIL_COMMAND_CARD_GET[] = "card-get";
static constexpr char VIRGIL_COMMAND_CARD_REVOKE[] = "card-revoke";
static constexpr char VIRGIL_COMMAND_CARD_SEARCH[] = "card-search";
static constexpr char VIRGIL_COMMAND_CONFIG[] = "config";
static constexpr char VIRGIL_COMMAND_DECRYPT[] = "decrypt";
static constexpr char VIRGIL_COMMAND_ENCRYPT[] = "encrypt";
static constexpr char VIRGIL_COMMAND_EXHASH[] = "exhash";
static constexpr char VIRGIL_COMMAND_KEY2PUB[] = "key2pub";
static constexpr char VIRGIL_COMMAND_KEYGEN[] = "keygen";
static constexpr char VIRGIL_COMMAND_SIGN[] = "sign";
static constexpr char VIRGIL_COMMAND_VERIFY[] = "verify";
static const char* VIRGIL_COMMAND_VALUES[] = {
    VIRGIL_COMMAND_CARD_CREATE,
    VIRGIL_COMMAND_CARD_GET,
    VIRGIL_COMMAND_CARD_REVOKE,
    VIRGIL_COMMAND_CARD_SEARCH,
    VIRGIL_COMMAND_CONFIG,
    VIRGIL_COMMAND_DECRYPT,
    VIRGIL_COMMAND_ENCRYPT,
    VIRGIL_COMMAND_EXHASH,
    VIRGIL_COMMAND_KEY2PUB,
    VIRGIL_COMMAND_KEYGEN,
    VIRGIL_COMMAND_SIGN,
    VIRGIL_COMMAND_VERIFY,
    nullptr
};

static constexpr char VIRGIL_CONFIG_APP_ACCESS_TOKEN[] = "APP_ACCESS_TOKEN";
static constexpr char VIRGIL_CONFIG_APP_KEY_DATA[] = "APP_KEY_DATA";
static constexpr char VIRGIL_CONFIG_APP_KEY_ID[] = "APP_KEY_ID";
static constexpr char VIRGIL_CONFIG_APP_KEY_PASSWORD[] = "APP_KEY_PASSWORD";
static const char* VIRGIL_CONFIG_VALUES[] = {
    VIRGIL_CONFIG_APP_ACCESS_TOKEN,
    VIRGIL_CONFIG_APP_KEY_DATA,
    VIRGIL_CONFIG_APP_KEY_ID,
    VIRGIL_CONFIG_APP_KEY_PASSWORD,
    nullptr
};

static constexpr char VIRGIL_DECRYPT_KEYPASS_PASSWORD[] = "password";
static constexpr char VIRGIL_DECRYPT_KEYPASS_PRIVKEY[] = "privkey";
static const char* VIRGIL_DECRYPT_KEYPASS_VALUES[] = {
    VIRGIL_DECRYPT_KEYPASS_PASSWORD,
    VIRGIL_DECRYPT_KEYPASS_PRIVKEY,
    nullptr
};

static constexpr char VIRGIL_ENCRYPT_RECIPIENT_ID_EMAIL[] = "email";
static constexpr char VIRGIL_ENCRYPT_RECIPIENT_ID_PASSWORD[] = "password";
static constexpr char VIRGIL_ENCRYPT_RECIPIENT_ID_PUBKEY[] = "pubkey";
static constexpr char VIRGIL_ENCRYPT_RECIPIENT_ID_VCARD[] = "vcard";
static const char* VIRGIL_ENCRYPT_RECIPIENT_ID_VALUES[] = {
    VIRGIL_ENCRYPT_RECIPIENT_ID_EMAIL,
    VIRGIL_ENCRYPT_RECIPIENT_ID_PASSWORD,
    VIRGIL_ENCRYPT_RECIPIENT_ID_PUBKEY,
    VIRGIL_ENCRYPT_RECIPIENT_ID_VCARD,
    nullptr
};

static constexpr char VIRGIL_EXHASH_ALG_SHA1[] = "sha1";
static constexpr char VIRGIL_EXHASH_ALG_SHA224[] = "sha224";
static constexpr char VIRGIL_EXHASH_ALG_SHA256[] = "sha256";
static constexpr char VIRGIL_EXHASH_ALG_SHA384[] = "sha384";
static constexpr char VIRGIL_EXHASH_ALG_SHA512[] = "sha512";
static const char* VIRGIL_EXHASH_ALG_VALUES[] = {
    VIRGIL_EXHASH_ALG_SHA1,
    VIRGIL_EXHASH_ALG_SHA224,
    VIRGIL_EXHASH_ALG_SHA256,
    VIRGIL_EXHASH_ALG_SHA384,
    VIRGIL_EXHASH_ALG_SHA512,
    nullptr
};

static constexpr char VIRGIL_KEYGEN_ALG_BP256R1[] = "bp256r1";
static constexpr char VIRGIL_KEYGEN_ALG_BP384R1[] = "bp384r1";
static constexpr char VIRGIL_KEYGEN_ALG_BP512R1[] = "bp512r1";
static constexpr char VIRGIL_KEYGEN_ALG_ED25519[] = "ed25519";
static constexpr char VIRGIL_KEYGEN_ALG_RSA3072[] = "rsa3072";
static constexpr char VIRGIL_KEYGEN_ALG_RSA4096[] = "rsa4096";
static constexpr char VIRGIL_KEYGEN_ALG_RSA8192[] = "rsa8192";
static constexpr char VIRGIL_KEYGEN_ALG_SECP192K1[] = "secp192k1";
static constexpr char VIRGIL_KEYGEN_ALG_SECP192R1[] = "secp192r1";
static constexpr char VIRGIL_KEYGEN_ALG_SECP224K1[] = "secp224k1";
static constexpr char VIRGIL_KEYGEN_ALG_SECP224R1[] = "secp224r1";
static constexpr char VIRGIL_KEYGEN_ALG_SECP256K1[] = "secp256k1";
static constexpr char VIRGIL_KEYGEN_ALG_SECP256R1[] = "secp256r1";
static constexpr char VIRGIL_KEYGEN_ALG_SECP384R1[] = "secp384r1";
static constexpr char VIRGIL_KEYGEN_ALG_SECP521R1[] = "secp521r1";
static const char* VIRGIL_KEYGEN_ALG_VALUES[] = {
    VIRGIL_KEYGEN_ALG_BP256R1,
    VIRGIL_KEYGEN_ALG_BP384R1,
    VIRGIL_KEYGEN_ALG_BP512R1,
    VIRGIL_KEYGEN_ALG_ED25519,
    VIRGIL_KEYGEN_ALG_RSA3072,
    VIRGIL_KEYGEN_ALG_RSA4096,
    VIRGIL_KEYGEN_ALG_RSA8192,
    VIRGIL_KEYGEN_ALG_SECP192K1,
    VIRGIL_KEYGEN_ALG_SECP192R1,
    VIRGIL_KEYGEN_ALG_SECP224K1,
    VIRGIL_KEYGEN_ALG_SECP224R1,
    VIRGIL_KEYGEN_ALG_SECP256K1,
    VIRGIL_KEYGEN_ALG_SECP256R1,
    VIRGIL_KEYGEN_ALG_SECP384R1,
    VIRGIL_KEYGEN_ALG_SECP521R1,
    nullptr
};

static constexpr char VIRGIL_SIGN_HASH_ALG_SHA1[] = "sha1";
static constexpr char VIRGIL_SIGN_HASH_ALG_SHA224[] = "sha224";
static constexpr char VIRGIL_SIGN_HASH_ALG_SHA256[] = "sha256";
static constexpr char VIRGIL_SIGN_HASH_ALG_SHA384[] = "sha384";
static constexpr char VIRGIL_SIGN_HASH_ALG_SHA512[] = "sha512";
static const char* VIRGIL_SIGN_HASH_ALG_VALUES[] = {
    VIRGIL_SIGN_HASH_ALG_SHA1,
    VIRGIL_SIGN_HASH_ALG_SHA224,
    VIRGIL_SIGN_HASH_ALG_SHA256,
    VIRGIL_SIGN_HASH_ALG_SHA384,
    VIRGIL_SIGN_HASH_ALG_SHA512,
    nullptr
};

static constexpr char VIRGIL_VERIFY_RECIPIENT_ID_PUBKEY[] = "pubkey";
static constexpr char VIRGIL_VERIFY_RECIPIENT_ID_VCARD[] = "vcard";
static const char* VIRGIL_VERIFY_RECIPIENT_ID_VALUES[] = {
    VIRGIL_VERIFY_RECIPIENT_ID_PUBKEY,
    VIRGIL_VERIFY_RECIPIENT_ID_VCARD,
    nullptr
};

static constexpr auto VIRGIL_VERBOSE_LEVEL_MIN = 1;
static constexpr auto VIRGIL_VERBOSE_LEVEL_MAX = 9;


}}} // cli::arg::value


#endif // VIRGIL_CLI_CPP11_API_H
