NAME
====

**card-revoke-private** -- revoke a Private Virgil Card from the Public
Keys Service

SYNOPSIS
========

        virgil card-revoke-private  -a <arg> [-f <file>] -k <file> [-p <arg>] [-V] [--]
                            [--version] [-h]

DESCRIPTION
===========

Revoke a Private Virgil Card from the Public Keys Service

OPTIONS
=======

        -a <arg>,  --card-id <arg>
         (required)  virgil Card identifier

        -f <file>,  --validated-identity <file>
         Validated identity. See 'virgil identity-confirm-private'

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

1.  Revoke a Private Virgil Card with a confirmed identity:

        virgil card-revoke -a <card_id> -f validated-identities.txt -k private.key

2.  Revoke Virgil Card with a confirmed identity:

        virgil card-revoke -a <card_id> -k private.key

SEE ALSO
========

virgil(1)  
card-create-private(1)  
public-key-revoke(1)
