NAME
====

**public-key-revoke** -- revoke the Card from the Public Keys Service

SYNOPSIS
========

        virgil public-key-revoke  {-f <file> ... |-d <arg> ... } -e <arg> -a <arg> -k
                          <file> [-p <arg>] [-V] [--] [--version] [-h]

DESCRIPTION
===========

Revoke a group of Cards from the Public Keys Service connected by
public-key-id + card-id of one of the Cards from the group

OPTIONS
=======

        -f <file>,  --validated-identity <file>  (accepted multiple times)
         (OR required)  Validated Identity for Private Virgil Card - see
         'virgil identity-confirm-private', for Global Virgil Card - see
         'virgil identity-confirm-global'
             -- OR --
        -d <arg>,  --identity <arg>  (accepted multiple times)
         (OR required)  User identifier for Private Virgil Card with
         unconfirmed identity. Use only for Private Virgil Card with
         unconfirmed identity


        -e <arg>,  --public-key-id <arg>
         (required)  Public Key identifier


        -a <arg>,  --card-id <arg>
         (required)  Globalr/Private Virgil Card identifier

        -k <file>,  --key <file>
         (required)  Private key

        -p <arg>,  --private-key-password <arg>
         Password to be used for Private Key encryption.

        -V,  --VERBOSE
         Show detailed information

        --,  --ignore_rest
         Ignores the rest of the labeled arguments following this flag.

        --version
         Displays version information and exits.

        -h,  --help
         Displays usage information and exits.

EXAMPLES
========

1.  Revoke a chain of Virgil Global Cards connected by public-key-id
    from Public Keys Service:

        virgil public-key-revoke -e <public_key_id> -a <card_id> -k alice/private.key -f alice/global-main-validated-identity.txt -f alice/global-reserve-validated-identity.txt

2.  Revoke a chain of Virgil Private Cards with confirmed identities
    connected by public-key-id from Public Keys Service:

        virgil public-key-revoke -e <public_key_id> -a <card_id> -k alice/private.key -f alice/private-main-validated-identity.txt -f alice/private-reserve-validated-identity.txt

3.  Revoke a chain of Virgil Private Cards with unconfirmed identities
    connected by public-key-id from Public Keys Service:

        virgil public-key-revoke -e <public_key_id> -a <card_id> -k alice/private.key -d email:alice_main@domain.com -d email:alice_reserve@domain.com

4.  Revoke a chain of Virgil Private Cards with unconfirmed identities
    and obfuscator identity value and/or type connected by public-key-id
    from Public Keys Service :

        virgil public-key-revoke -e <public_key_id> -a <card_id> -k alice/private.key -d <obfuscator_type>:<obfuscator_value_1> -d <obfuscator_type>:<obfuscator_value_2>

SEE ALSO
========

virgil(1)  
card-create-global(1)  
card-create-private(1)  
public-key-revoke(1)
