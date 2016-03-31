NAME
====

**sign** -- sign data

SYNOPSIS
========

**virgil sign** \[-i *file*\] \[-o *file*\] -k *file* \[-p *arg*\]
\[-V\] \[--\] \[--version\] \[-h\]

DESCRIPTION
===========

Sign data with given user's Private Key.

OPTIONS
=======

    -i *file*,  --in *file*
     Data to be signed. If omitted, stdin is used.

    -o *file*,  --out *file*
     Digest sign. If omitted, stdout is used.

    -k *file*,  --key *file*
     (required)  Signer's Private Key.

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

        virgil sign -i plain.txt -o plain.txt.sign -k private.key

SEE ALSO
========

[`virgil(1)`](../markdown/virgil.1.md),  
[`verify(1)`](../markdown/verify.1.md)
