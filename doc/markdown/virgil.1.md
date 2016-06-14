NAME
====

virgil\*\* -- command line tool for using Virgil Security full stack functionality.

SYNOPSIS
========

virgil\*\* *command* \[*command\_opts*\] \[*command\_args*\]

DESCRIPTION
===========

The **Virgil** program is a command line tool for using Virgil Security stack functionality:

-   encrypt, decrypt, sign and verify data;
-   interact with Virgil Keys Service;
-   interact with Virgil Private Keys Service.

COMMON COMMANDS
===============

**keygen** Generate [a private key](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#private-key) with provided parameters.

**key2pub** Extract [a public key](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#public-key) from the private key.

**encrypt** Encrypt data for given recipients who can be defined by their Virgil Keys and by passwords.

**decrypt** Decrypt data for a given recipient who can be defined by his public key or by his password.

**sign** Sign data with the private key.

**verify** Verify data and signature with the public key.

**exhash** Derives hash from the given data with [PBKDF function](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#pbkdf-function).

**config** Get information about Virgil CLI configuration file.

IDENTITY SERVICE COMMANDS
=========================

**identity-confirm-global**  
Confirmation of the Identity. Returns validation\_token which is required for operations with [Global Virgil Cards](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#global-card) and [the confirmed Identity](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#confirmed-identity):

1.  **card-create-global**;
2.  **card-revoke-global**;
3.  **public-key-revoke-global**.

**identity-confirm-private** Confirmation of the Identity. Returns the validation\_token which is required for the operations with [Private Virgil Cards](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#private-card) and the confirmed identity:

1.  **card-create-private**;
2.  **card-revoke-private**;
3.  **public-key-revoke-private**.

**identity-verify** Verify an identity Returns [action id](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#action-id).

**identity-valid** Validates the passed token. Checks whether [time](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#time-to-live) and [usage](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#count-to-live) limits for [validation token](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#validation-token) are not exceeded.

KEYS SERVICE COMMANDS
=====================

**public-key-get** Get user's Virgil Public Key from the Virgil Keys service.

**public-key-revoke-global** Revoke a group of Global Virgil Cards from the Public Keys Service connected by [public-key-id](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#public-key-id) + [card-id](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#card-id) of one of the Cards from the group.

**public-key-revoke-private** Revoke a group of Private Virgil Cards from the Public Keys Service connected by [public-key-id](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#public-key-id) + [card-id](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#card-id) of one of the Cards from the group.

VIRGIL CARD SERVICE COMMANDS
============================

**card-create-global** Create a Global Virgil Card. This means **identity-verify** **identity-confirm-global**.

**card-create-private** Create a Private Virgil Card. This means **identity-confirm-private**.

**card-search-global** Search for a Global Virgil Card from the Virgil Keys Service by:

1.  application\_name - search an application Global Virgil Card.
2.  email - search a Global Virgil Card.

**card-search-private** Search the Private Virgil Card from the Virgil Keys Service.

**card-get** **card-get** Get user's [Virgil Card](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Glossary#card) from the Virgil Keys service.

**card-revoke-private** Revoke a Private Virgil Card by the card-id.

**card-revoke-global** Revoke a Global Virgil Card by the card-id.

PRIVATE KEYS SERVICE COMMANDS
=============================

**private-key-add** Add existing the private key to the Private Keys Service.

**private-key-get** Get the private key from the Virgil Private Keys Service.

**private-key-del** Delete the private key object from the Private Keys Service.

SEE ALSO
========

virgil-keygen(1)
virgil-key2pub(1)
virgil-encrypt(1)
virgil-decrypt(1)
virgil-sign(1)
virgil-verify(1)
virgil-exhash(1)
virgil-config(1)
virgil-identity-confirm-global(1)
virgil-identity-confirm-private(1)
virgil-identity-verify(1)
virgil-identity-valid(1)
virgil-public-key-get(1)
virgil-public-key-revoke-global(1)
virgil-public-key-revoke-private(1)
virgil-card-create-global(1)
virgil-card-create-private(1)
virgil-card-search-global(1)
virgil-card-search-private(1)
virgil-card-revoke-private(1)
virgil-card-revoke-global(1)
virgil-private-key-add(1)
virgil-private-key-get(1)
virgil-private-key-del(1)
