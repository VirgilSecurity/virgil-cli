NAME
====

**public-key-revoke** -- revoke the Card from the Public Keys Service

SYNOPSIS
========

**virgil public-key-revoke** {-f *file* ... |-d *arg* ... } -e *arg* -a
*arg* -k *file* \[--\] \[--version\] \[-h\]

DESCRIPTION
===========

Revoke a group of Cards from the Public Keys Service connected by
public-key-id + card-id of one of the Cards from the group

OPTIONS
=======

    -f *file*,  --validated-identities *file*  (accepted multiple times)
     (OR required)  ValidatedIdentity
         -- OR --
    -d *arg*,  --identity *arg*  (accepted multiple times)
     (OR required)  Identity user


    -e *arg*,  --public-key-id *arg*
     (required)  Public Key identifier


    -a *arg*,  --card-id *arg*
     (required)  Virgil Card identifier одной из Карточек в цепочки

    -k *file*,  --key *file*
     (required)  Private key

    --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag

    --version
     Displays version information and exits

    -h,  --help
     Displays usage information and exits

EXAMPLES
========

1.  Revoke a group of Cards with confirmed Identities connected by
    public-key-id from the Public Keys Service:

        virgil public-key-revoke -e *public_key_id* -a *card_id* -k private.key -f validated-identity.txt

2.  Revoke a group of Cards with unconfirmed Identities connected by
    public-key-id from the Public Keys Service:

        virgil public-key-revoke -e *public_key_id* -a *card_id* -k private.key -d email:user1@domain.com
            -d email:user2@domain.com

SEE ALSO
========

[`virgil(1)`]()  
[`card-create(1)`]()  
[`public-key-revoke(1)`]()
