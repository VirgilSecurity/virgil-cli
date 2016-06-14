NAME
====

**public-key-get** -- get the global/private Virgil Public Key from the
Virgil Keys Service.

SYNOPSIS
========

        virgil public-key-get  [-o <file>] -e <arg> [-V] [--] [--version] [-h]

DESCRIPTION
===========

This utility allows you to get a public key by its `public-key-id`.

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

1.  Get a public key by its
    [`public-key-id`](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#public-key-id):

        virgil public-key-get -o public.vkey -e <public_key_id>

SEE ALSO
========

**virgil**(1)  
**virgil-config**(1)  
**virgil-card-get**(1)  
**virgil-card-search-global**(1)  
**virgil-card-search-private**(1)  
**virgil-card-create-global**(1)  
**virgil-card-create-private**(1)
