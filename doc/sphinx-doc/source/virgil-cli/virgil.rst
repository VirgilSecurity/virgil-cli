******
virgil
******

========
SYNOPSIS
========
::

  virgil command [command opts] [command args]

===========
DESCRIPTION
===========
The **Virgil** program is a command line tool for using Virgil Security stack functionality:

-   encrypt, decrypt, sign and verify data;
-   interact with Virgil Keys Service;
-   interact with Virgil Private Keys Service.


===============
COMMON COMMANDS
===============
**virgil-keygen(1)**
Generate a private key with provided parameters.

**virgil-key2pub(1)**
Extract a public key from the private key.

**virgil-encrypt(1)**
Encrypt data for given recipients who can be defined by their Virgil Keys and by passwords.

**virgil-decrypt(1)**
Decrypt data for a given recipient who can be defined by his public key or by his password.

**virgil-sign(1)**
Sign data with the private key.

**virgil-verify(1)**
Verify data and signature with the public key.

**virgil-exhash(1)**
Derives hash from the given data with PBKDF function.

**virgil-config(1)**
Get information about Virgil CLI configuration file.


=========================
IDENTITY SERVICE COMMANDS
=========================
**virgil-identity-confirm-global(1)**  
Confirmation of the Identity. Returns validation token which is required for operations with Global Virgil Cards and the confirmed Identity:

#.  **virgil-card-create-global(1)**;
#.  **virgil-card-revoke-global(1)**;
#.  **virgil-public-key-revoke-global(1)**.

**virgil-identity-confirm-private(1)** 
Confirmation of the Identity. Returns the validation token which is required for the operations with Private Virgil Cards and the confirmed identity:

#.  **virgil-card-create-private(1)**;
#.  **virgil-card-revoke-private(1)**;
#.  **virgil-public-key-revoke-private(1)**.

**virgil-identity-verify(1)**
Verify an identity Returns action id.

**virgil-identity-valid(1)**
Validates the passed token. Checks whether time to live and usage count to live limits for validation token are not exceeded.


=====================
KEYS SERVICE COMMANDS
=====================
**virgil-public-key-get(1)**
Get user's Virgil Public Key from the Virgil Keys service.

**virgil-public-key-revoke-global(1)**
Revoke a group of Global Virgil Cards from the Public Keys Service connected by public-key-id + card-id of one of the Cards from the group.

**virgil-public-key-revoke-private(1)**
Revoke a group of Private Virgil Cards from the Public Keys Service connected by public-key-id + card-id of one of the Cards from the group.


============================
VIRGIL CARD SERVICE COMMANDS
============================
**virgil-card-create-global(1)**
Create a Global Virgil Card. This means **virgil-identity-verify(1)** **virgil-identity-confirm-global(1)**.

**virgil-card-create-private(1)**
Create a Private Virgil Card. This means **virgil-identity-confirm-private(1)**.

**virgil-card-search-global(1)**
Search for a Global Virgil Card from the Virgil Keys Service by:

#. application name - search an application global Virgil Card.
#. email - search a global Virgil Card.

**virgil-card-search-private(1)**
Search the Private Virgil Card from the Virgil Keys Service.

**virgil-card-get(1)**
Get user's Virgil Card from the Virgil Keys service.

**virgil-card-revoke-private(1)**
Revoke a Private Virgil Card by the card-id.

**virgil-card-revoke-global(1)**
Revoke a Global Virgil Card by the card-id.


=============================
PRIVATE KEYS SERVICE COMMANDS
=============================
**virgil-private-key-add(1)**
Add existing the private key to the Private Keys Service.

**virgil-private-key-get(1)**
Get the private key from the Virgil Private Keys Service.

**virgil-private-key-del(1)**
Delete the private key object from the Private Keys Service.


========
SEE ALSO
========
* virgil-quickstart(1)
* virgil-keygen(1)
* virgil-key2pub(1)
* virgil-encrypt(1)
* virgil-decrypt(1)
* virgil-sign(1)
* virgil-verify(1)
* virgil-exhash(1)
* virgil-config(1)
* virgil-identity-confirm-global(1)
* virgil-identity-confirm-private(1)
* virgil-identity-verify(1)
* virgil-identity-valid(1)
* virgil-public-key-get(1)
* virgil-public-key-revoke-global(1)
* virgil-public-key-revoke-private(1)
* virgil-card-create-global(1)
* virgil-card-create-private(1)
* virgil-card-search-global(1)
* virgil-card-search-private(1)
* virgil-card-revoke-private(1)
* virgil-card-revoke-global(1)
* virgil-private-key-add(1)
* virgil-private-key-get(1)
* virgil-private-key-del(1)
