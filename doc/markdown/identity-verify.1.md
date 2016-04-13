NAME
====

**identity-confirm** -- confirm an Identity

SYNOPSIS
========

**virgil identity-verify** -d <arg> \[-o <file>\] \[-V\] \[--\]
\[--version\] \[-h\]

DESCRIPTION
===========

Confirm identity

OPTIONS
=======

-d <arg>, --identity <arg> (required) Identity email

-o <file>, --out <file> Action id. If omitted stdout is used.

-V, --VERBOSE Show detailed information

--, --ignore\_rest Ignores the rest of the labeled arguments following
this flag.

--version Displays version information and exits.

-h, --help Displays usage information and exits.

RETURN VALUE
============

On success, *action\_id* is returned. On error, throw exeption.

EXAMPLES
========

    virgil identity-verify -d email:user@domain.com

SEE ALSO
========

[`virgil(1)`](../markdown/virgil.1.md),  
[`identity-confirm(1)`](../markdown/identity-confirm.1.md),
