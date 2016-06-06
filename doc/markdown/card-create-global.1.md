NAME
====

**card-create-global** -- create a Global Virgil Card

SYNOPSIS
========

       virgil card-create-global  {-e <arg>|--public-key <file>} {-d <arg>|-f <file>}
                           [-o <file>] -k <file> [-p <arg>] [-V] [--]
                           [--version] [-h]

DESCRIPTION
===========

Global Virgil Card is a base of building the net of trust between users.

Connections between Cards can be created. Model many-to-many is
implemented in PKI. It means that we can have Cards with:

1.  one Public Key and *different* Identities;
2.  one Public Key and *one* identity;
3.  different Public Keys and *different* Identities;
4.  different Public Keys and *one* Identity;
5.  one Public Key and *one* Identity connected with public-key-id;
6.  one Public Key and *different* identities connected
    with public-key-id.

OPTIONS
=======

        -e <arg>,  --public-key-id <arg>
         (OR required)  Public key identifier
             -- OR --
        --public-key <file>
         (OR required)  Public key


        -d <arg>,  --identity <arg>
         (OR required)  Identity: email
             -- OR --
        -f <file>,  --validated-identity <file>
         (OR required)  Validated identity (see 'virgil
         identity-confirm-global')


        -o <file>,  --out <file>
         virgil Card. If omitted, stdout is used.

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

1.  Create a Global Virgil Card:

        virgil card-create-global -f alice/validated_identity_global.txt --public-key public.key -k alice/private.key -o alice/my_card.vcard

2.  Create a Global Virgil Card, with confirming of identity:

        virgil card-create-global -d alice@domain.com --public-key public.key -k alice/private.key -o alice/my_card.vcard

3.  Create a connection with already existing Global Virgil Card, by
    public-key-id:

        virgil card-create-global -f alice/validated_identity_global.txt -e <pub_key_id> -k alice/private.key -o alice/my_card.vcard

4.  Create a connection with already existing Global Virgil Card,
    by public-key-id. With confirming of identity:

        virgil card-create-global -d alice@domain.com -e <pub_key_id> -k alice/private.key -o alice/my_card.vcard

SEE ALSO
========

virgil(1)  
keygen(1)  
identity-confirm-global(1)
