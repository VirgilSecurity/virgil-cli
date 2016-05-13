NAME
====

**private-key-get** -- get the Private Key from the Private Key Service

SYNOPSIS
========

        virgil private-key-get  [-o <file>] -a <arg> -f <file> [-V] [--] [--version]
                        [-h]

DESCRIPTION
===========

Get the Private Key from the Private Key Service

OPTIONS
=======

        -o <file>,  --out <file>
         Private Key. If omitted, stdout is used.

        -a <arg>,  --card-id <arg>
         (required)  virgil Card identifier

        -f <file>,  --validated-identity <file>
         (required)  Validated identity

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

        virgil private-key-get -a *card_id* -f validated_identity.txt -o private.vkey

SEE ALSO
========

virgil(1)  
keygen(1)  
private-key-add(1)  
identity-confirm-private(1)  
identity-confirm-global(1)
