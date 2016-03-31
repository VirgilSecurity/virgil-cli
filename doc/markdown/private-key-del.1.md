NAME
====

**private-key-del** -- delete the Private Key from the Private Keys
Service

SYNOPSIS
========

**virgil private-key-del** -a <arg> -k <file> \[-p <arg>\] \[-V\] \[--\]
\[--version\] \[-h\]

DESCRIPTION
===========

Delete the Private Key from the Private Keys Service.

OPTIONS
=======

    -a <arg>,  --card-id <arg>
     (required)  virgil Card identifier

    -k <file>,  --key <file>
     (required)  Private Key

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

        virgil private-key-del -k private.key -a *card_id*

SEE ALSO
========

[`virgil(1)`](../markdown/virgil.1.md),  
[`keygen(1)`](../markdown/keygen.1.md),  
[`identity-confirm(1)`](../markdown/identity-confirm.1.md)
