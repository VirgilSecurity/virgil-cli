NAME
====

**public-key-get** -- return Public Key

SYNOPSIS
========

**virgil public-key-get** \[-o *file*\] -e *arg* \[--\] \[--version\]
\[-h\]

DESCRIPTION
===========

Return the Public Key by Public Key id

OPTIONS
=======

    -o *file*,  --out *file*
     Virgil Public Key. If omitted, stdout is used

    -e *arg*,  --public-key-id *arg*
     (required)  Public Key identifier


    --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag

    --version
     Displays version information and exits

    -h,  --help
     Displays usage information and exits

EXAMPLES
========

        virgil public-key-get -o public.vkey -e *public_key_id*

SEE ALSO
========

[`virgil(1)`](../markdown/virgil.1.md),  
[`card-get(1)`](../markdown/card-get.1.md),  
[`card-search(1)`](../markdown/card-search.1.md),  
[`card-create(1)`](../markdown/card-create.1.md)
