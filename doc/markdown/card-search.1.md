NAME
====

**card-search** -- search for Card(s) by Identity using filters

SYNOPSIS
========

**virgil card-search** \[-o *arg*\] -d *arg* \[-u\] \[-V\] \[--\]
\[--version\] \[-h\] *card-id* ...

DESCRIPTION
===========

Search for Cards by email using filters: 1. by signed Cards with
*signed-card-id*; 1. including Cards with an unconfirmed Identity into
the search.

OPTIONS
=======

    -o *arg*,  --out *arg*
     Folder in which will be saved a Virgil Cards

    -d *arg*,  --identity *arg*
     (required)  Identity: email

    -u,  --unconfirmed
     Search Cards include unconfirmed identity

    -V,  --VERBOSE
     Show detailed information

    --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag.

    --version
     Displays version information and exits.

    -h,  --help
     Displays usage information and exits.

    *card-id*  (accepted multiple times)
     Signed card id

EXAMPLES
========

1.  Search for Cards with a confirmed Identity:

        virgil card-search -d email:alice@gmail.com -o alice/

2.  Search for Cards with a confirmed Identity and
    uncorfirmaed Identity.

        virgil card-search -d email:alice@gmail.com -o alice/ -u

3.  Search for Cards with an email, which have signed (
    [`card-sign(1)`](../markdown/card-sign.1.md) ) the Cards with
    card-id

        virgil card-search -d email:alice@gmail.com -u *user1_card_id* *user2_card_id*

SEE ALSO
========

[`virgil(1)`](../markdown/virgil.1.md),  
[`card-create(1)`](../markdown/card-create.1.md),  
[`card-get(1)`](../markdown/card-get.1.md),  
[`card-sign(1)`](../markdown/card-sign.1.md)
