NAME
====

**encrypt** -- encrypt data for given recipients

SYNOPSIS
========

**virgil encrypt** \[-i *file*\] \[-o *file*\] \[-c *file*\] \[--\]
\[--version\] \[-h\] *recipient* ...

DESCRIPTION
===========

The utility allows you to encrypt data with a password or combination of
Public Key + recipient-id. recipient-id is an identifier which will be
connected with Public Key. If a *sender* has a Card, his recipient-id is
the Card's id. Also Public Keys is saved in the Card.

OPTIONS
=======

    -i *file*,  --in *file*
     Data to be encrypted. If omitted, stdin is used

    -o *file*,  --out *file*
     Encrypted data. If omitted, stdout is used

    -c *file*,  --content-info *file*
     Content info - meta information about encrypted data. If omitted,
     becomes a part of the encrypted data

    --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag

    --version
     Displays version information and exits

    -h,  --help
     Displays usage information and exits

    *recipient*  (accepted multiple times)
     Contains information about one recipient

     Format:

     [pass|id|vcard|email|pub-key]:<value*

     where:

        * if pass, then *value* - recipient's password;

        * if id, then *value* - recipient's UUID associated with Virgil

         Card identifier;

        * if vcard, then *value* - recipient's Virgil Card file

          stored locally;

        * if email, then *value* - recipient's email, поиск осуществляется только для

        Cards with a confirmed Identity;

        * if pub-key, then *value* - recipient's Public Key.

EXAMPLES
========

1.  Alice encrypts the data for Bob using his email:

        virgil encrypt -i plain.txt -o plain.txt.venc email:bob@domain.com

2.  Alice encrypts the data for Bob and Tom using their emails:

        virgil encrypt -i plain.txt -o plain.txt.venc email:bob@domain.com email:tom@domain.com

3.  Alice encrypts the data with a password:

        virgil encrypt -i plain.txt -o plain.txt.venc pass:strong_password

4.  Alice encrypts the data with a combination of Public Key +
    recipient-id. You will be asked to enter recipient-id:

        virgil encrypt -i plain.txt -o plain.txt.venc pub-key:public.key

SEE ALSO
========

[`virgil(1)`](../markdown/virgil.1.md),  
[`decrypt(1)`](../markdown/decrypt.1.md)
