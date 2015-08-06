NAME
====

**sign** -- sign data.

SYNOPSIS
========

**virgil sign** [--in *file*] [--out *file*] --key *file* [--pwd *arg*]

DESCRIPTION
===========

Sign data with given user's private key.

OPTIONS
=======

-i *file*, --in *file*  
Data to be signed. If omitted stdin is used.

-o *file*, --out *file*  
Digest sign. If omitted stdout is used.

-k *file*, --key *file*  
Signer's private key.

-p *arg*, --pwd *arg*  
Signer's private key password.

SEE ALSO
========

`virgil(1)`, `virgilverify(1)`
