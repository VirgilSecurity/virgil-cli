NAME
====

**virgil** -- command line tool for using Virgil Security full stack
functionality.

SYNOPSIS
========

**virgil** *command* \[*command\_opts*\] \[*command\_args*\]

DESCRIPTION
===========

The **Virgil** program is a command line tool for using Virgil Security
stack functionality:

-   encrypt, decrypt, sign and verify data;
-   interact with Virgil Keys Service;
-   interact with Virgil Private Keys Service.

COMMON COMMANDS
===============

**keygen**  
Generate Private Key with given parameters.

**key2pub**  
Extract Public Key from the Private Key.

**encrypt**  
Encrypt data for given recipients which can be defined by Virgil Keys
and by passwords.

**decrypt**  
Decrypt data for given recipient which can be defined by Virgil Public
Key or by password.

**sign**  
Sign data with Private Key.

**verify**  
Verify data and signature with Public Key.

**hash**  
Derives the obfuscated data from incoming parameters using
PBKDF function.

IDENTITY SERVICE COMMANDS
=========================

**identity-confirm-global**  
Confirmation of the Identity. Returns validation\_token which is
required for operations with Cards and confirmed identity:

1.  `card-create-global(1)`;
2.  `card-revoke-global(1)`;
3.  `public-key-revoke-global(1)`.

**identity-confirm-private**  
Confirmation of the Identity. Returns validation\_token which is
required for operations with Cards and confirmed identity:

1.  `card-create-private(1)`;
2.  `card-revoke-private(1)`;
3.  `public-key-revoke-private(1)`.

**identity-verify**  
Verify an identity Returns action\_id.

**identity-validate**  
Validates the passed token. Checks whether validation\_token is valid.
It has time and usage limits.

KEYS SERVICE COMMANDS
=====================

**public-key-get**  
Get user's Virgil Public Key from the Virgil Keys service.

**public-key-revoke-global**  
Revoke a group of Global Virgil Cards from the Public Keys Service
connected by public-key-id + card-id of one of the Cards from the group

**public-key-revoke-private**  
Revoke a group of Private Virgil Cards from the Public Keys Service
connected by public-key-id + card-id of one of the Cards from the group

VIRGIL CARD SERVICE COMMANDS
============================

**card-create-global**  
Create a Global Virgil Card. Creates a Global Virgil Card. This means
identity-verify; identity-confirm-global.

**card-create-private**  
Create a Private Virgil Card. Creates a Private Virgil Card. This
means identity-confirm-private.

**card-search-global**  
Search Card by email or application name search

**card-search-private**  
Search Card by type:value; search including Cards with unconfirmed
Identity;

**card-get**  
Get user's Virgil Card from the Virgil Keys service.

**card-revoke-private**  
Revoke a Private Virgil Card by card-id.

**card-revoke-global**  
Revoke a Global Virgil Card by card-id.

PRIVATE KEYS SERVICE COMMANDS
=============================

**private-key-add**  
Add existing Private Key to the Private Keys Service.

**private-key-get**  
Get Private Key from the Virgil Private Keys Service.

**private-key-del**  
Delete Private Key object from the Private Keys Service.

SEE ALSO
========

keygen(1)  
key2pub(1)  
encrypt(1)  
decrypt(1)  
sign(1)  
verify(1)  
hash(1)  
identity-verify(1)  
identity-confirm-global(1)  
identity-confirm-private(1)  
identity-valid(1)  
public-key-get(1)  
public-key-revoke-global(1)  
public-key-revoke-private(1)  
card-create-global(1)  
card-create-private(1)  
card-search-global(1)  
card-search-private(1)  
card-get(1)  
card-revoke-private(1)  
card-revoke-global(1)  
private-key-add(1)  
private-key-get(1)  
private-key-del(1)
