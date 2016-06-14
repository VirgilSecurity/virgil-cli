NAME
====

**hash** -- derives the obfuscated data from incoming parameters using
\[PBKDF
function\](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary\#pbkdf
function.

SYNOPSIS
========

        virgil hash  [-i <file>] [-o <file>] -s <file> [-a <sha1|sha224|sha256|sha384
             |sha512>] [-c <int>] [-V] [--] [--version] [-h]

DESCRIPTION
===========

Derives the obfuscated data from incoming parameters using PBKDF
function.

OPTIONS
=======

        -i <file>,  --in <file>
         The string value to be hashed. If omitted, stdout is used.

        -o <file>,  --out <file>
         Obfuscated data. If omitted, stdout is used.

        -s <file>,  --salt <file>
         (required)  The hash salt.

        -a <sha1|sha224|sha256|sha384|sha512>,  --algorithm <sha1|sha224|sha256
          |sha384|sha512>
         Generate hash with one of the following positions:

            * sha1 -   secure Hash Algorithm 1;

            * sha224 - secure Hash Algorithm 2  that are 224 bits;

            * sha256 - secure Hash Algorithm 2  that are 256 bits;

            * sha384 - secure Hash Algorithm 2  that are 384 bits(default);

            * sha512 - secure Hash Algorithm 2  that are 512 bits;


        -c <int>,  --iterations <int>
         The count of iterations. Default - 2048

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

1.  Generate hash (alg - sha384, iterations - 2048 default):

        virgil hash -i data.txt -o obfuscated_data.txt -s data_salt.txt

2.  Generate hash sha512 and count of iterations - 4096:

        virgil hash -i data.txt -o obfuscated_data.txt -s data_salt.txt -a sha512 -c 4096

SEE ALSO
========

**virgil**(1)  
**virgil-card-create-private**(1)
