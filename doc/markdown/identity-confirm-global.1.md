NAME
====

**identity-confirm-global** -- confirm identity for a Global Virgil Card

SYNOPSIS
========

        virgil identity-confirm-global  [-o <file>] [-d <arg>] [--action-id <arg>]
                                [--confirmation-code <arg>] [-t <int>] [-c
                                <int>] [-V] [--] [--version] [-h]

DESCRIPTION
===========

It is required to pass **identity-confirm** if you want to confirm your
Identity so that other people can be sure that a received signature,
encrypted data came from you. After entering your email
*confirmation\_code* will be sent to you, you have to enter it to
receive a validated-identity. **validated-identity** consists of
*validation\_token* and your Identity. It is required for the following
operations:

1.  create a Global Virgil Card;
2.  revoke a Global Virgil Card, a group of Cards;
3.  get a Private key from the Private Keys Service.

OPTIONS
=======

        -o <file>,  --out <file>
         Validated identity. If omitted, stdout is used.

        -d <arg>,  --identity <arg>
         Identity email

        --action-id <arg>
         Action id.

        --confirmation-code <arg>
         Confirmation code

        -t <int>,  --time-to-live <int>
         Time to live, by default = 3600.

        -c <int>,  --count-to-live <int>
         Count to live, by default = 2.

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

On success, *validated identity model*:

    {
        "type": "email",
        "value": "alice@gmail.com",
        "validation_token": *validation_token*
    }

is returned. On error, throw exeption.

EXAMPLES
========

1.  Identity confirmation with requests number limit = 2 and time
    validity limit = 3600:

        virgil identity-confirm-global -d email:alice@gmail.com -o validated-identity.txt

2.  Identity confirmation with requests number limit = 10 and time
    validity limit = 60:

        virgil identity-confirm-global -d email:alice@gmail.com -o validated-identity.txt -l 60 -c 10

3.  Identity confirmation with requests number limit = 2 and time
    validity limit = 3600:

        virgil identity-confirm-global --action-id <action_id> --confirmation-code <code> -o alice/validated-identity.txt

SEE ALSO
========

virgil(1)  
card-create-global(1)  
card-revoke-global(1)  
private-key-get(1)
