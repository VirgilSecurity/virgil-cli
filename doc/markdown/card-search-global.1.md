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

Search for a Global Virgil Card from the Virgil Keys Service by:

1.  application\_name - search an application Virgil Global Card
2.  email - search a Virgil Global Card

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

1.  The global search Global Virgil Cards by email:

        virgil card-search-global -e alice@mailinator.com -o alice/

2.  The global search for application Global Virgil Cards by application
    name:

        virgil card-search-global -c <app_name> -o all_app_cards/

3.  Get all application cards:

        virgil card-search-global -c "com.virgilsecurity.*" -o all_app_cards/

SEE ALSO
========

virgil(1)  
card-create-global(1)  
card-get(1)
