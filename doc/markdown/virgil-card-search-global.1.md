NAME
====

**card-search-global** -- search for [a global Virgil
Card](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#global-virgil-card)
from the Virgil K

SYNOPSIS
========

        virgil card-search-global  {-e <arg>|-c <arg>} [-o <arg>] [-V] [--] [--version]
                           [-h]

DESCRIPTION
===========

The utility allows you to search for a global Virgil Card from the
Virgil Keys Service by:

1.  `application_name` - search an application global Virgil Card.
2.  `email` - search a global Virgil Card.

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

1.  The global search global Virgil Cards by email:

        virgil card-search-global -e alice@mailinator.com -o alice/

2.  The global search for application global Virgil Cards by application
    name:

        virgil card-search-global -c <app_name> -o all_app_cards/

3.  Get all application cards:

        virgil card-search-global -c "com.virgilsecurity.*" -o all_app_cards/

SEE ALSO
========

**virgil**(1)  
**virgil-config**(1)  
**virgil-card-create-global**(1)  
**virgil-card-get**(1)
