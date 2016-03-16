NAME
====

**private-key-del** -- delete the Private Key from the Private Keys
Service

SYNOPSIS
========

**virgil private-key-del** -a *arg* -k *file* \[--\] \[--version\]
\[-h\]

DESCRIPTION
===========

Delete the Private Key from the Private Keys Service.

OPTIONS
=======

    -a *arg*,  --card-id *arg*
     (required)  Virgil Card identifier

    -k *file*,  --key *file*
     (required)  Private Key

    --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag

    --version
     Displays version information and exits

    -h,  --help
     Displays usage information and exits

EXAMPLES
========

        virgil private-key-del -k private.key -a *card_id*

SEE ALSO
========

[`keygen(1)`](../markdown/keygen.1.md)  
[`identity-confirm(1)`](../markdown/identity-confirm.1.md)
