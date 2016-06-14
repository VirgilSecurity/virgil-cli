NAME
====

**config** -- get information about Virgil CLI configuration file.

SYNOPSIS
========

        virgil config  [-o <file>] [-g] [-l] [-t] [--] [--version] [-h]

DESCRIPTION
===========

Get information about Virgil CLI configuration file.

If don't set Virgil Access Token during the application build (cmake
-DVIRGIL\_ACCESS\_TOKEN = <VIRGIL_ACCESS_TOKEN> ..) or whether it should
be changed, you can create a configuration file.

With 'virgil config' utility you can find out what path should be based
on a configuration file and how it should look.

The Virgil Access Token definitely need for following utilites.

Private Virgil Card:

1.  **virgil-card-create-private**(1)
2.  **virgil-card-revoke-private**(1)
3.  **virgil-public-key-revoke-private**(1)
4.  **virgil-card-search-private**(1)

Global Virgil Card:

1.  **virgil-identity-verify**(1)
2.  **virgil-identity-valid**(1)
3.  **virgil-identity-confirm-global**(1)

4.  **virgil-card-create-global**(1)
5.  **virgil-card-revoke-global**(1)
6.  **virgil-public-key-revoke-global**(1)
7.  **virgil-card-search-global**(1)

Common:

1.  **virgil-card-get**(1)

2.  **virgil-public-key-get**(1)

3.  **virgil-private-key-add**(1)
4.  **virgil-private-key-get**(1)
5.  **virgil-private-key-del**(1)

Part of the functionality, which refers to the search for Cards on
Virgil Keys Service:

1.  **virgil-verify**(1)
2.  **virgil-encrypt**(1)
3.  **virgil-decrypt**(1)

OPTIONS
=======

        -o <file>,  --out <file>
         If omitted, stdout is used.


        -g,  --global
         Show path to the configuration file applied for all users.

        -l,  --local
         Show path to the configuration file applied for current user.

        -t,  --template
         Show configuration file template.

        --,  --ignore_rest
         Ignores the rest of the labeled arguments following this flag.

        --version
         Displays version information and exits.

        -h,  --help
         Displays usage information and exits.

EXAMPLES
========

1.  Show path to the configuration file applied for all users:

        virgil config --global

2.  Show path to the configuration file applied for current user:

        virgil config --local

3.  Show configuration file template:

        virgil config --template

SEE ALSO
========

**virgil**(1)
