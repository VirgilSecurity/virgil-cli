NAME
====

**identity-verify** -- verify an Identity for Global Virgil Card

SYNOPSIS
========

        virgil identity-verify  -d <arg> [-o <file>] [-V] [--] [--version] [-h]

DESCRIPTION
===========

Verify an Identity for Global Virgil Card

OPTIONS
=======

        -d <arg>,  --identity <arg>
         (required)  Identity email

        -o <file>,  --out <file>
         Action id. If omitted stdout is used.

        -V,  --VERBOSE
         Show detailed information

        --,  --ignore_rest
         Ignores the rest of the labeled arguments following this flag.

        --version
         Displays version information and exits.

        -h,  --help
         Displays usage information and exits.

RETURN VALUE
============

On success, <action_id> is returned. On error, throw exeption.

EXAMPLES
========

        virgil identity-verify -d email:user@domain.com

SEE ALSO
========

virgil(1)  
identity-confirm-global(1)
