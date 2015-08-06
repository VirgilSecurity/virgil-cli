NAME
====

**keyget** -- get user's Virgil Public Key from the Virgil Public Keys
service.

SYNOPSIS
========

**virgil keyget** [--out *file*] *user\_id...*

DESCRIPTION
===========

Get user's Virgil Public Key from the Virgil Public Keys service.

OPTIONS
=======

-o *file*, --out *file*  
Virgil Public Key. If omitted stdout is used.

*user\_id*  
(required) User's identifer.

Format:

    [email|phone|domain]:<value>

where:

-   if `email`, then *value* - user's email;
-   if `phone`, then *value* - user's phone;
-   if `domain`, then *value* - user's domain.

SEE ALSO
========

`virgil(1)`, `virgilkeygen(1)`, `virgilkeyreg(1)`
