NAME
====

**keygen** -- generate private key with given parameters.

SYNOPSIS
========

**virgil keygen** [--ec *curve* | --rsa *nbits*] [--out *file*] [--pwd
*arg*] [--format *arg*]

DESCRIPTION
===========

Generate private key with given parameters.

OPTIONS
=======

-e *curve*, --ec *curve*  
Generate elliptic curve key with one of the following curves:

-   `bp256r1` - 256-bits Brainpool curve;
-   `bp384r1` - 384-bits Brainpool curve;
-   `bp512r1` - 512-bits Brainpool curve (default);
-   `secp192r1` - 192-bits NIST curve;
-   `secp224r1` - 224-bits NIST curve;
-   `secp256r1` - 256-bits NIST curve;
-   `secp384r1` - 384-bits NIST curve;
-   `secp521r1` - 521-bits NIST curve;
-   `secp192k1` - 192-bits "Koblitz" curve;
-   `secp224k1` - 224-bits "Koblitz" curve;
-   `secp256k1` - 256-bits "Koblitz" curve.

-r *nbits*, --rsa *nbits*  
Generate RSA key with a given number of bits.

-o *file*, --out *file*  
Private key. If omitted stdout is used.

-p *arg*, --pwd *arg*  
Password to be used for private key encryption. If omitted private key
is stored in the plain format.

SEE ALSO
========

`virgil(1)`, `virgilkey2pub(1)`
