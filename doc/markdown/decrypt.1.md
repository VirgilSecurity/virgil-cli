NAME
====

**decrypt** -- decrypt data with given password or given Private Key

SYNOPSIS
========

        virgil decrypt  [-i <file>] [-o <file>] [-c <file>] [-k <file>] [-p <arg>] -r
                <arg> [-V] [--] [--version] [-h]

DESCRIPTION
===========

Decrypt data with given password or given Private Key + recipient-id.
recipient-id is an identifier which is connected with Public Key. If a
*sender* has a Card, his recipient-id is Card's id. Also Public Key is
saved in the Card.

OPTIONS
=======

        -i <file>,  --in <file>
         Data to be decrypted. If omitted, stdin is used.

        -o <file>,  --out <file>
         Decrypted data. If omitted, stdout is used.

        -c <file>,  --content-info <file>
         Content info. Use this option if content info is not embedded in the
         encrypted data.

        -k <file>,  --key <file>
         Private Key.

        -p <arg>,  --private-key-password <arg>
         Password to be used for Private Key encryption.

        -r <arg>,  --recipient <arg>
         (required)  Recipient defined in format:

         [password|id|vcard|email|private]:<value>

         where:

            * if password, then <value> - recipient's password;

            * if id, then <value> - recipient's UUID associated with Virgil Card
         identifier;

            * if vcard, then <value> - recipient's Virgil Card/Cards file

              stored locally;

            * if email, then <value> - recipient's email;

            * if private, then set type:value for searching Private Virgil Card[s].

         For example: private:email:<obfuscator_email>. ( obfiscator - see
         'virgil hash')


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

1.  Decrypt data for user identified by password:

        virgil decrypt -i plain.txt.enc -o plain.txt -k private.key -r password:strong_password

2.  Decrypt data for Bob identified by his Private Key + recipient-id
    \[id|vcard|email|private\]:

        virgil decrypt -i plain.txt.enc -o plain.txt -k bob/private.key -r id:<recipient_id>

SEE ALSO
========

virgil(1)  
encrypt(1)
