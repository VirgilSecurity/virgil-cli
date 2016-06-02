NAME
====

**public-key-get** -- get Global/Private Virgil Public Key from the
Public Key Service

SYNOPSIS
========

        virgil public-key-get  [-o <file>] -e <arg> [-V] [--] [--version] [-h]

DESCRIPTION
===========

Get Global/Private Virgil Public Key from the Public Key Service by
Public Key id

OPTIONS
=======

        -o <file>,  --out <file>
        virgil Public Key. If omitted, stdout is used.

        -e <arg>,  --public-key-id <arg>
        (required)  Global/Private Public Key identifier


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

        virgil public-key-get -o public.vkey -e <public_key_id>

SEE ALSO
========

virgil(1)  
card-get(1)  
card-search-global(1)  
card-search-private(1)  
card-create-global(1)  
card-create-private(1)
