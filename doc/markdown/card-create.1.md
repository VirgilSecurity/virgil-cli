NAME
====

**card-create** -- create a Card

SYNOPSIS
========

**virgil card-create** {--public-key *file*|-e *arg*} {-d *arg*|-f
*file*} \[-o *file*\] -k *file* \[--\] \[--version\] \[-h\]

DESCRIPTION
===========

Virgil Card is a base of building the net of trust between users. There
are two types of Cards: 1. with a confirmed identity.
*validated\_identity* is required, it can be obtained in
[`identity-confirm(1)`](../markdown/identity-confirm.1.md) 2. with an
unconfirmed identity.

A Card with a confirmed Identity guarantees that a user with given email
has been checked.

A Card with an unconfirmed Identity lets use Public Keys Service
infrastructure while staying anonymous. There is *no way* to turn a Card
with an unconfirmed Identity into a Card with a confirmed Identity!

Connections between Cards can be created. Model many-to-many is
implemented in PKI. It means that we can have Cards with:  
1. one Public Key and *different* Identities;  
1. one Public Key and *one* identity;  
1. different Public Keys and *different* Identities;  
1. different Public Keys and *one* Identity;  
1. one Public Key and *one* Identity connected with public-key-id;  
1. one Public Key and *different* identities connected with
public-key-id.

OPTIONS
=======

    --public-key *file*
    (OR required)  Public key
     -- OR --
    -e *arg*,  --public-key-id *arg*
    (OR required)  Public key identifier

    -d *arg*,  --identity *arg*
    (OR required)  Identity: email
     -- OR --
    -f *file*,  --validated-identities *file*
    (OR required)  Validated identity

    -o *file*,  --out *file*
    Virgil Card. If omitted, stdout is used.

    -k *file*,  --key *file*
    (required)  Private key

    --,  --ignore_rest
    Ignores the rest of the labeled arguments following this flag.

    --version
    Displays version information and exits.

    -h,  --help
    Displays usage information and exits.

EXAMPLES
========

1.  Create a Card with a confirmed Identity

        virgil card-create -f validated-identity.txt --public-key public.key -k private.key -o my_card.vcard

2.  Create a connection with an already existing Card with a confirmed
    Identity by public-key-id

        virgil card-create -f validated-identity.txt --public-key-id *public_key_id* -k private.key -o my_card.vcard

3.  Create a Card with an unconfirmed Identity

        virgil card-create -d email:anonim@gmail.com --public-key public.key -k private.key -o my_card.vcard

4.  Create a connection with an already existing Card with an
    unconfirmed Identity by public-key-id

        virgil card-create -d email:anonim@gmail.com --public-key-id *public_key_id* -k private.key -o my_card.vcard

SEE ALSO
========

[`virgil(1)`](../markdown/virgil.1.md)  
[`keygen(1)`](../markdown/keygen.1.md),  
[`identity-confirm(1)`](../markdown/identity-confirm.1.md)
