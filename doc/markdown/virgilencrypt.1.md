NAME
====

**encrypt** -- encrypt data for given recipients.

SYNOPSIS
========

**virgil encrypt** [--in *file*] [--out *file*] [--content-info *file*]
[--recipients *file*] *recipient* *...*

DESCRIPTION
===========

Encrypt data for given recipients. Recipient can be represented either
by the password, or by the Virgil Public Key.

OPTIONS
=======

-i *file*, --in *file*  
Data to be encrypted. If omitted stdin is used.

-o *file*, --out *file*  
Encrypted data. If omitted stdout is used.

-c *file*, --content-info *file*  
Content info - meta information about encrypted data. If omitted becomes
a part of the encrypted data.

-r *file*, --recipients *file*  
(accepted multiple times) File that contains information about
recipients. Each line can be either empty line, or comment line, or
recipient defined in format:

    [pass|file|email|phone|domain]:<value>

where:

-   if `pass`, then *value* - recipient's password;
-   if `file`, then *value* - recipient's Virgil Public Key file stored
    locally;
-   if `email`, then *value* - recipient's email;
-   if `phone`, then *value* - recipient's phone;
-   if `domain`, then *value* - recipient's domain.

*recipient*  
(accepted multiple times) Contains information about one recipient. Same
as significant line in the recipients configuration file.

SEE ALSO
========

`virgil(1)`, `virgildecrypt(1)`