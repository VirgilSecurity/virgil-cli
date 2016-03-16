NAME
====

**identity-confirm** -- confirm an Identity

SYNOPSIS
========

**virgil identity-confirm** \[-o *file*\] -d *arg* \[-l *int*\] \[-r
*int*\] \[--\] \[--version\] \[-h\]

DESCRIPTION
===========

It is required to pass **identity-confirm** if you want to confirm your
Identity so that other people can be sure that a received signature,
encrypted data came from you. After entering your email
*confirmation\_code* will be sent to you, you have to enter it to
receive a validated-identity. **validated-identity** consists of
*validation\_token* and your Identity. It is required for the following
operations:  
1. create a Card with a confirmed Identity;  
1. revoke a Card, a group of Cards;  
1. get a Private key from the Private Keys Service.

OPTIONS
=======

    -o *file*,  --out *file*
     Validated identity. If omitted, stdout is used

    -d *arg*,  --identity *arg*
     (required)  Identity email

    -l *int*,  --time-to-live *int*
     Time limit for validation-token,  by default = 3600

    -r *int*,  --count-to-live *int*
     Requests number limit for validation-token, by default = 10.
     All requests where validation-token is used except *identity-valid* are counted.

    --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag

    --version
     Displays version information and exits

    -h,  --help
     Displays usage information and exits

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

1.  Identity confirmation with requests number limit = 10 and time
    validity limit = 3600:

        virgil identity-confirm -d email:alice@gmail.com -o validated-identity.txt

2.  Identity confirmation with requests number limit = 1 and time
    validity limit = 60:

        virgil identity-confirm -d email:alice@gmail.com -o validated-identity.txt -l 60 -r 1

SEE ALSO
========

[`card-create(1)`]()  
[`card-revoke(1)`]()  
[`private-key-get(1)`]()
