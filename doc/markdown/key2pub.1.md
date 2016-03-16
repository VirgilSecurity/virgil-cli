NAME
====

**key2pub** -- get Public Key from the Private Key Service

SYNOPSIS
========

**virgil key2pub** \[-i *file*\] \[-o *file*\] \[--\] \[--version\]
\[-h\]

DESCRIPTION
===========

Get Public Key from the given Private Key

OPTIONS
=======

    -i *file*,  --in *file*
     Private key. If omitted, stdin is used.

    -o *file*,  --out *file*
     Public key. If omitted, stdout is used.

    --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag.

    --version
     Displays version information and exits.

    -h,  --help
     Displays usage information and exits.

EXAMPLES
========

        virgil key2pub -i private.key -o public.key

SEE ALSO
========

[`keygen(1)`](../markdown/keygen.1.md)
