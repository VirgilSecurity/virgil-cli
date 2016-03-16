NAME
====

**card-search-app** -- search for application Cards

SYNOPSIS
========

**virgil card-search-app** \[-o <arg>\] -c <arg> \[--\] \[--version\]
\[-h\]

DESCRIPTION
===========

Search for application Cards

OPTIONS
=======

    -o *file*,  --out *file*
     Application cards. If omitted, stdout is used

    -c *arg*,  --application-name *arg*
     (required) Application name, if application name = '*' - get all Application Cards from Public Keys Service

    --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag

    --version
     Displays version information and exits

    -h,  --help
     Displays usage information and exits

EXAMPLES
========

1.  Search for application Cards:

        virgil card-search-app -c *app_name* -o app_cards/

2.  Return all application Card:

        virgil card-search-app -c "*" -o all_app_cards/

SEE ALSO
========

[`virgil(1)`]() [`card-create(1)`]() [`card-get(1)`]()
