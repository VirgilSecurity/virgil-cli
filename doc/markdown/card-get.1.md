NAME
====

**card-get** -- return Global/Private Virgil Card\[s\]

SYNOPSIS
========

        virgil card-get [-o <arg>] -a <arg> [-e <arg>] [-k <file>] [-p <arg>] [-V]
                     [--] [--version] [-h]

DESCRIPTION
===========

Return a Card by card-id or a group of Cards connected with
public-key-id

OPTIONS
=======

        -o <arg>,  --out <arg>
         Folder in which will be saved a Virgil Cards

        -a <arg>,  --card-id <arg>
         (required)  Global/Private Virgil Card identifier

        -e <arg>,  --public-key-id <arg>
         Public Key identifier


        -k <file>,  --key <file>
         Private key

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

1.  Return a Private/Global Virgil Card by card-id:

        virgil card-get -a <card_id> -o cards/

2.  Return a group of Private/Global Virgil Cards connected with
    public-key-id, card-id belongs to one of the Cards:

        virgil card-get -a <card_id> -e <public_key_id> -k private.key -o cards/

SEE ALSO
========

virgil(1)  
card-create(1)  
card-search-global(1)  
card-search-private(1)
