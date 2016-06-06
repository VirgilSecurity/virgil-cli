NAME
====

**card-revoke-global** -- revoke a Global Virgil Card from the Public
Keys Service

SYNOPSIS
========

        virgil card-revoke-global  {-d <arg>|-f <file>} -a <arg> -k <file> [-p <arg>]
                           [-V] [--] [--version] [-h]

DESCRIPTION
===========

Revoke a Global Virgil Card from the Public Keys Service

OPTIONS
=======

        -d <arg>,  --identity <arg>
         (OR required)  Identity: email:alice@domain.com
             -- OR --
        -f <file>,  --validated-identity <file>
         (OR required)  Validated identity (see 'virgil
         identity-confirm-global')


        -a <arg>,  --card-id <arg>
         (required)  virgil Card identifier

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

1.  Revoke a Global Virgil Card:

        virgil card-revoke-global -a <card_id> -f validated-identities.txt -k private.key

2.  Revoke a Global Virgil Card with a confirming identity:

        virgil card-revoke-global -a <card_id> -d alice@domain.com -k alice/private.key

SEE ALSO
========

virgil(1)  
card-create-global(1)  
public-key-revoke(1)
