NAME
====

**reconfirm** -- resend confirmation code.

SYNOPSIS
========

**virgil reconfirm** --user-id *arg*

DESCRIPTION
===========

Resend confirmation code to the user for given user's identifier.

OPTIONS
=======

-i *arg*, --user-id *arg*  
(required) User's identifer.

Format:

    [email|phone|domain]:<value>

where:

-   if `email`, then *value* - user's email;
-   if `phone`, then *value* - user's phone;
-   if `domain`, then *value* - user's domain.

SEE ALSO
========

`virgil(1)`, `virgilkeyreg(1)`
