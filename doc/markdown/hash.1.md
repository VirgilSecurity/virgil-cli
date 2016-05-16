NAME
====

**hash** -- derives the obfuscated data from incoming parameters using
PBKDF function.

SYNOPSIS
========

        virgil hash  [-i <file>] [-o <file>] -s <string> [-a <sha1|sha224|sha256|sha384
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

        -s <string>,  --salt <string>
         (required)  The hash salt.

        -a <sha1|sha224|sha256|sha384|sha512>,  --algorithm <sha1|sha224|sha256
          |sha384|sha512>
         Generate hash with oneof the following positions:

            * sha1 -   secure Hash Algorithm 1;

            * sha224 - hash algorithm;

            * sha256 - hash algorithm;

            * sha384 - hash algorithm(default);

            * sha512 - hash algorithm;


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

        virgil hash -i data.txt -o obfuscated_data.txt -s SALT

2.  Generate hash sha512 and count of iterations - 4096:

        virgil hash -i data.txt -o obfuscated_data.txt -s SALT -a sha512 -c 4096

SEE ALSO
========

virgil(1)  
card-create-private(1)
