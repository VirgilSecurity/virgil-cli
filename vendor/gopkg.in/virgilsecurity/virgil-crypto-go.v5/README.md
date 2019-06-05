# Virgil Security Go Crypto Library
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-crypto-go.png?branch=v5)](https://travis-ci.org/VirgilSecurity/virgil-crypto-go)

### [Introduction](#introduction) | [Library purposes](#library-purposes) | [Usage examples](#usage-examples) | [Installation](#installation) | [Docs](#docs) | [License](#license) | [Contacts](#support)

## Introduction
VirgilCrypto is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and an open-source high-level [cryptographic library](https://github.com/VirgilSecurity/virgil-crypto) that allows you to perform all necessary operations for securely storing and transferring data in your digital solutions. Crypto Library is written in C++ and is suitable for mobile and server platforms.

Virgil Security, Inc., guides software developers into the forthcoming security world in which everything will be encrypted (and passwords will be eliminated). In this world, the days of developers having to raise millions of dollars to build a secure chat, secure email, secure file-sharing, or a secure anything have come to an end. Now developers can instead focus on building features that give them a competitive market advantage while end-users can enjoy the privacy and security they increasingly demand.

## Library purposes
* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* PFS (Perfect Forward Secrecy)

## Usage examples

#### Generate a key pair

Generate a Private Key with the default algorithm (EC_X25519):
```go
crypto := virgil_crypto_go.NewVirgilCrypto()
keypair, err := crypto.GenerateKeypair()

```

#### Generate and verify a signature

Generate signature and sign data with a private key:
```go
crypto := virgil_crypto_go.NewVirgilCrypto()

// prepare a message
dataToSign := []byte("Hello, Bob!")

// generate signature
signature, err := crypto.Sign(dataToSign, privateKey)
```

Verify a signature with a public key:
```go
crypto := virgil_crypto_go.NewVirgilCrypto()

// verify signature using Alice's Card
err := crypto.VerifySignature(dataToSign, signature, alicePublicKey)

```
#### Encrypt and decrypt data

Encrypt Data on a Public Key:

```go
crypto := virgil_crypto_go.NewVirgilCrypto()

// prepare a message
message := []byte("Hello, Bob!")

// encrypt the message
encrypted, err := crypto.Encrypt(message, bobPublicKey)

```

Decrypt the encrypted data with a Private Key:

```go
crypto := virgil_crypto_go.NewVirgilCrypto()

// decrypt the encrypted data using a private key
decrypted, err := crypto.Decrypt(encryptedMessage, bobPrivateKey)
```

## Installation

The package is supported only Linux and Mac OS X. Please make sure [all dependencies](https://github.com/VirgilSecurity/virgil-crypto#build-prerequisites) are installed on your system first.

Set GOPATH variable as described [here](https://github.com/golang/go/wiki/SettingGOPATH)

To install the latest wrapper version run:
```
go get -d -u gopkg.in/virgilsecurity/virgil-crypto-go.v5
```
and then run:
```
cd $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v5/
make
```
Depending on your choice of crypto implementation you should create crypto instance by calling:

```go
virgil_crypto_go.NewVirgilCrypto()
```
or

```
cryptoimpl.NewVirgilCrypto()
```

## Docs
- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)
- [More usage examples](https://developer.virgilsecurity.com/docs/how-to#cryptography)

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://join.slack.com/t/VirgilSecurity/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).
