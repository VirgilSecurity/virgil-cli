NAME
====

**private-key-add** -- add the Private Key to Private Key Service

SYNOPSIS
========

**virgil private-key-add** -a *arg* -k *file* \[-p *arg*\] \[-V\] \[--\]
\[--version\] \[-h\]

DESCRIPTION
===========

General statements:

1.  Make sure that you have registered and confirmed your account for
    the Public Keys Service.
2.  Make sure that you have a public/private key pair and you have
    already uploaded the public key to the Public Keys Service.
3.  Make sure that you have your private key on local machine.
4.  Make sure that you have registered an application at [Virgil
    Security, Inc](https://developer.virgilsecurity.com/account/signup).

OPTIONS
=======

    -a *arg*,  --card-id *arg*
     (required)  virgil Card identifier

    -k *file*,  --key *file*
     (required)  Private Key

    -p *arg*,  --private-key-password *arg*
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

        virgil private-key-add -k private.key -a *card_id*

SEE ALSO
========

[`virgil(1)`](../markdown/virgil.1.md),  
[`private-key-del(1)`](../markdown/private-key-del.1.md),  
[`keygen(1)`](../markdown/keygen.1.md),  
[`identity-confirm(1)`](../markdown/identity-confirm.1.md)
