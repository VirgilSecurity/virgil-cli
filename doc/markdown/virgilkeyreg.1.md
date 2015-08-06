NAME
====

**keyreg** -- register user's public key on the Virgil Public Keys
service.

SYNOPSIS
========

**virgil keyreg** [--in *file*] [--out *file*] *user\_id* *...*

DESCRIPTION
===========

Register user's public key on the Virgil Public Keys service. If
registration successfull confirmation code will be sent to the user.

OPTIONS
=======

-i *file*, --in *file*  
Public key. If omitted stdin is used.

-o *file*, --out *file*  
Virgil Public Key. If omitted stdout is used.

*user\_id*  
(required) User's identifer.

Format: [email|phone|domain]:\<value\>  
where:

-   if email, then <value> - user's email;
-   if phone, then <value> - user's phone;
-   if domain, then <value> - user's domain.

SEE ALSO
========

`virgil(1)`, `virgilkeygen(1)`, `virgilkeyget(1)`, `virgilconfirm(1)`
