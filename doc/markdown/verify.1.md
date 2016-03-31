NAME
====

**verify** -- verify data and signature

SYNOPSIS
========

**virgil verify** \[-i <file>\] \[-o <file>\] -s <file> -r <arg> \[-V\]
\[--\] \[--version\] \[-h\]

DESCRIPTION
===========

Verify data and signature with given user's identifier or with its
Public Key.

OPTIONS
=======

    -i <file>,  --in <file>
     Data to be verified. If omitted, stdin is used.

    -o <file>,  --out <file>
     Verification result: success | failure. If omitted, stdout is used.

    -s <file>,  --sign <file>
     (required)  Digest sign.

    -r <arg>,  --recipient <arg>
     (required)  Recipient defined in format:

     [id|vcard|email|pubkey]:<value>

     where:

        * if id, then <value> - recipient's UUID associated with Virgil Card
     identifier;

        * if vcard, then <value> - recipient's Virgil Card/Cards file

          stored locally;

        * if email, then <value> - recipient's email;

        * if pubkey, then <value> - recipient's Public Key.


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

        virgil verify -i plain.txt -s plain.txt.sign -r email:bob@gmail.com


        virgil verify -i plain.txt -s plain.txt.sign -r pubkey:bob/public.key

SEE ALSO
========

[`virgil(1)`](../markdown/virgil.1.md),  
[`sign(1)`](../markdown/sign.1.md)
