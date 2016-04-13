[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-cli.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-cli)

# Virgil Security CLI

- [Quickstart](#quickstart)
- [Motivation](#motivation)
    - [Using virgil-cli with committing to services](#using-virgil-cli-with-committing-to-services)
        - [Generate Keys](#generate-keys)
        - [Create a Virgil Card](#create-a-virgil-card)
        - [Encrypt and decrypt data](#encrypt-and-decrypt-data)
        - [Sign and verify data](#sign-and-verify-data)
    - [Using virgil-cli without committing to services](#using-virgil-cli-without-committing-to-services)
        - [Encrypt and decrypt data](#encrypt-and-decrypt-data)
        - [Sign and verify data](#sign-and-verify-data)
- [Build: Unix](#build-unix)
    - [Unix toolchain](#unix-toolchain)
    - [Unix build steps](#unix-build-steps)
- [Build: Windows MSVC](#build-windows-msvc)
    - [Windows MSVC toolchain](#windows-msvc-toolchain)
    - [Windows MSVC build steps](#windows-msvc-build-steps)
- [Manuals](#manuals)
- [License](#license)
- [Contacts](#contacts)


## Quickstart

## Motivation
The **virgil** program is a command line tool for using Virgil Security
stack functionality:

-   encrypt, decrypt, sign and verify data;
-   interact with Virgil Keys Service;
-   interact with Virgil Private Keys Service.

## Using virgil cli with committing to services

Let's create two users Alice and Bob and demonstrate the communication between them.
```
mkdir alice
mkdir bob
```

Scenario for Alice is shown below, parlicularly [Generate Keys](#generate-keys) and [Create a Virgil Card](#create-a-virgil-card).
The same actions are performed for Bob.

### Generate Keys

1.  Generate default [Private Key](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Entities#private-key)(Elliptic 384-bits NIST Curve).
You will be asked to enter the Private key password:

        virgil keygen -o alice/private.key

1.  Extracted a [Public Key](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Entities#public-key) from the Private Key

        virgil key2pub -i private.key -o alice/public.key

### Create a [Virgil Card](https://github.com/VirgilSecurity/virgil/wiki/Virgil-Entities#virgil-card)

1. Confirming Identity.

        virgil identity-confirm -d email:alice@mailinator.com -o alice/validated-identity.txt

1.  Create a Virgil Card:

        virgil card-create -f alice/validated-identity.txt --public-key alice/public.key -k alice/private.key
            -o alice/alice-vs.vcard


## Encrypt and decrypt data
1. Encrypt.
Alice encrypts plain.txt for Bob. Alice needs Bob's Card to encrypt some data for Bob.
She can get it from the Public Keys Service by indicating Bob's email.
Encrypt data for Bob identified by email:

        virgil encrypt -i plain.txt -o plain.txt.enc email:bob@mailinator.com

1. Decrypt.
Bob decrypts plain.txt.enc with his Private key and his Card.
Bob decrypts the data on his side:

        virgil decrypt -i plain.txt.enc -k bob/private.key -r vcard:bob/bob.vcard

## Sign and verify data
1. Sign. Private Key is required in order to make a signature.
Alice signs data:

        virgil sign -i plain.txt -o plain.txt.sign -k alice/private.key


1. Verify. Bob verifies Alice's signature. He needs Alice's Card to verify the signature.
It can be received from the Public Keys Service by indicating Alice's email.

        virgil verify -i plain.txt -s plain.txt.sign -r email:alice@mailinator.com



<br>


## Using virgil-cli without committing to services


## Encrypt and decrypt data
1. Encrypt.
Alice encrypts plain.txt for Bob. Alice must have Bob's Public key + recipient's identifier
in order to encrypt the data for Bob.
pubkey - argument, which contains Public Key and recipient's identifier.
recipient's identifier - is plain text, which is needed for the Public key association.
Encrypt data for Bob :

        virgil encrypt -i plain.txt -o plain.txt.enc pubkey:bob/public.key:ForBob

1. Decrypt
Bob decrypts plain.txt.enc using his Private Key and recipient's identifier, which has been provided by Alice.
Bob decrypts the data on his side:

        virgil decrypt -i plain.txt.enc -k bob/private.key -r id:ForBob

## Sign and verify data
1. Sign. Bob signs the data:

        virgil sign -i plain.txt -o plain.txt.sign -k alice/private.key

1. Verify. Bob verifies Alice's signature. He must have Alice's Public key to verify the signature.

        virgil verify -i plain.txt -s plain.txt.sign -r pubkey:alice/public.key


## Build Unix

###  Unix toolchain
*   [CMake](http://www.cmake.org/) (accessible in command prompt). Minimum version: 3.2.
*   [Git](http://git-scm.com/) (accessible in command prompt).
*   [libcurl](http://curl.haxx.se/libcurl/).


### Unix build steps
1.   Open terminal

1.   Clone project

            git clone https://github.com/VirgilSecurity/virgil-cli.git

1.   Go to the project's folder.

            cd virgil-cli

1.   Checkout specific branch if needed.

1.   Create folder for the build purposes and go to it

            mkdir build && cd build

1.   Configure, build and install

            cmake .. && make && make install

1.   Check installation

            virgil --version


## Build Windows MSVC

### Windows MSVC toolchain
*   [Visual Studio 2015](https://www.visualstudio.com/)
*   [CMake](http://www.cmake.org/) (accessible in command prompt). Minimum version: 3.2.
*   [Git](http://git-scm.com/) (accessible in command prompt).
*   [NSIS](http://nsis.sourceforge.net/).


### Windows MSVC build steps

1.   Open `Visual Studio Command Prompt`

1.   Clone project

            git clone https://github.com/VirgilSecurity/virgil-cli.git

1.   Go to the project's folder.

            cd virgil-cli

1.   Checkout specific branch if needed.

1.   Create folder for the build purposes and go to it

            mkdir build
            cd build

1.   Configure, build and make installer

            cmake -G"NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ..
            nmake
            nmake package

1.   Check installer under `build` directory

            dir /B | findstr /R /C:"virgil-cli-*"

## Manuals
See manual pages [here](doc/markdown/virgil.1.md).


## License
BSD 3-Clause. See [LICENSE](https://github.com/VirgilSecurity/virgil-cli/blob/master/LICENSE) for details.


## Contacts

Email: <support@virgilsecurity.com>
