NAME
====

**card-search-global** -- the global search for the applications Virgil
Card\[s\]

SYNOPSIS
========

        virgil card-search-global  {-e <arg>|-c <arg>} [-o <arg>] [-V] [--] [--version]
                           [-h]

DESCRIPTION
===========

Search for a Global Virgil Card from the Virgil Keys Service

OPTIONS
=======

        -e <arg>,  --email <arg>
         (OR required)  email
             -- OR --
        -c <arg>,  --application-name <arg>
         (OR required)  Application name, name = 'com.virgilsecurity.*' - get
         all Cards

        -o <arg>,  --out <arg>
         Folder in which will be saved a Virgil Cards

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

1.  The global search for application Cards by email:

        virgil card-search-global -e <app_name> -o app_cards/

2.  The global search for application Cards by application name:

        virgil card-search-global -c "com.virgilsecurity.*" -o all_app_cards/

SEE ALSO
========

virgil(1)  
card-create-global(1)  
card-get(1)
