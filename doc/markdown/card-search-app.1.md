NAME
====

**card-search-app** -- search for application Cards

SYNOPSIS
========

**virgil card-search-app** \[-o <arg>\] -c <arg> \[-V\] \[--\]
\[--version\] \[-h\]

DESCRIPTION
===========

Search for application Cards

OPTIONS
=======

    -o <arg>,  --out <arg>
     Folder in which will be saved a Virgil Cards

    -c <arg>,  --application-name <arg>
     (required)  Application name, name = '*' - get all Cards


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

1.  Search for application Cards:

        virgil card-search-app -c *app_name* -o app_cards/

2.  Return all application Card:

        virgil card-search-app -c "*" -o all_app_cards/

SEE ALSO
========

[`virgil(1)`](../markdown/virgil.1.md),  
[`card-create(1)`](../markdown/card-create.1.md),  
[`card-get(1)`](../markdown/card-get.1.md)
