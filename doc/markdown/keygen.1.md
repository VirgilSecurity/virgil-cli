NAME
====

**keygen** -- generate Private Key with given parameters

SYNOPSIS
========

**virgil keygen** \[-o *file*\] \[-e
*bp256r1|bp384r1|bp512r1|secp192r1|secp224r1
|secp256r1|secp384r1|secp521r1|secp192k1|secp224k1|secp256k1*\] \[-r
*rsa3072|rsa4096|rsa8192*\] \[-p\] \[--\] \[--version\] \[-h\]

DESCRIPTION
===========

Generate Elliptic Curve Private Key or RSA Private Key.

OPTIONS
=======

    -o *file*,  --out *file*
     Private key. If omitted, stdout is used

    -e *bp256r1|bp384r1|bp512r1|secp192r1|secp224r1|secp256r1|secp384r1
      |secp521r1|secp192k1|secp224k1|secp256k1*,  --ec *bp256r1|bp384r1
      |bp512r1|secp192r1|secp224r1|secp256r1|secp384r1|secp521r1|secp192k1
      |secp224k1|secp256k1*
     Generate elliptic curve key with one of the following curves:

        * bp256r1 - 256-bits Brainpool curve;

        * bp384r1 - 384-bits Brainpool curve;

        * bp512r1 - 512-bits Brainpool curve (default);

        * secp192r1 - 192-bits NIST curve;

        * secp224r1 - 224-bits NIST curve;

        * secp256r1 - 256-bits NIST curve;

        * secp384r1 - 384-bits NIST curve;

        * secp521r1 - 521-bits NIST curve;

        * secp192k1 - 192-bits "Koblitz" curve;

        * secp224k1 - 224-bits "Koblitz" curve;

        * secp256k1 - 256-bits "Koblitz" curve.


    -r *rsa3072|rsa4096|rsa8192*,  --rsa *rsa3072|rsa4096|rsa8192*
     Generate RSA key with one of the following positions:

        * rsa3072;

        * rsa4096;

        * rsa8192

    -p,  --key-pwd
     Password input switch. It is off by default. If it is on, input for entering
     password will be opened

    --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag

    --version
     Displays version information and exits

    -h,  --help
     Displays usage information and exits

EXAMPLES
========

1.  Generate Elliptic 512-bits Brainpool Curve Private Key(default):

        virgil keygen -o private.key

2.  Generate Elliptic Curve Private Key with password protection:

        virgil keygen -o private.key -p

3.  Generate Elliptic 521-bits NIST Curve Private Key:

        virgil keygen -o private.key -e secp521r1

4.  Generate RSA Private Key:

        virgil keygen -r rsa8192 -o private.key

SEE ALSO
========

[`key2pub(1)`]()
