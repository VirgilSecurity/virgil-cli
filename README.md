[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-cli.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-cli)

# Virgil Security CLI

- [Motivation](#motivation)
- [Quickstart](#quickstart)
    - [Using virgil-cli without committing to services](#using-virgil-cli-without-committing-to-services)
        - [Generate Keys](#generate-keys)
        - [Encrypt data](#encrypt-data)
        - [Decrypt data](#decrypt-data)
        - [Sign data](#sign-data)
        - [Verify data](#verify-data)
    - [Using virgil-cli with committing to services](#using-virgil-cli-wit-committing-to-services)
        - [Create a Virgil Card](#create-a-virgil-card)
        - [Encrypt/decrypt](#encrypt/decrypt)
        - [Sign/verify](#sign/verify)
- [Build: Unix](#build-unix)
    - [Toolchain](#unix-toolchain)
    - [Build steps](#unix-build-steps)
- [Build: Windows MSVC](#build-windows-msvc)
    - [Toolchain](#windows-msvc-toolchain)
    - [Build steps](#windows-msvc-build-steps)
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


## Using virgil-cli without committing to services

### Generate Keys

Generate Elliptic Curve Private Key or RSA Private Key.

1.  Generate Elliptic 384-bits NIST Curve Private Key(default):

        virgil keygen -o private.key

1.  Generate Elliptic Curve Private Key with password protection:

        virgil keygen -o private.key -p STRONGPASS

1.  Generate Elliptic 521-bits NIST Curve Private Key:

        virgil keygen -o private.key -e secp521r1

1.  Generate RSA Private Key:

        virgil keygen -r rsa8192 -o private.key

1.  Extracted a Public Key from the Private Key

        virgil key2pub -i private.key -o public.key


### Encrypt

    virgil encrypt -i plain.txt -o plain.txt.enc pubkey:alice-vs/public.key:ForAlice

### Decrypt

    virgil decrypt -i plain.txt.enc -k alice-vs/private.key -r id:ForAlice

### Sign

    virgil sign -i plain.txt -o plain.txt.sign -k alice-vs/private.key


### Verify

    virgil verify -i plain.txt -s plain.txt.sign -r pubkey:alice-vs/public.key


<br>


## Using virgil-cli with committing to services

### Create a Virgil Card

1. Confirming Identity:

        virgil identity-confirm -d email:alice-vs@mailinator.com -o alice-vs/validated-identity.txt

1.  Create a Virgil Card:

        virgil card-create -f alice-vs/validated-identity.txt --public-key alice-vs/public.key -k alice-vs/private.key -o alice-vs/alice-vs.vcard


## Encrypt/decrypt
1. Encrypt
Encrypt data for Bob identified by email:

        virgil encrypt -i plain.txt -o plain.txt.enc email:bob-vs@mailinator.com

1. Decrypt
Bob decrypts the data on his side:

        virgil decrypt -i plain.txt.enc -k bob-vs/private.key -r vcard:bob-vs/bob-vs.vcard

1.  Encrypt for multiple recipients.
    Encrypt data for Bob and Tom identified by emails:

        virgil encrypt -i plain.txt -o plain.txt.enc email:bob-vs@mailinator.com email:tom-vs@mailinator.com


## Sign/verify
1. Sign. Alice signs data

        virgil sign -i plain.txt -o plain.txt.sign -k alice-vs/private.key

1. Verify. Bob verifies Alice's signature

        virgil verify -i plain.txt -s plain.txt.sign -r email:alice-vs@mailinator.com

## Unix Build

### Toolchain
*   [CMake](http://www.cmake.org/) (accessible in command prompt). Minimum version: 3.2.
*   [Git](http://git-scm.com/) (accessible in command prompt).
*   [Python](https://www.python.org/) (accessible in command prompt). Minimum version: 2.7.
*   [Python YAML](http://pyyaml.org/).
*   [libcurl](http://curl.haxx.se/libcurl/).

### Build steps
1.   Open terminal

1.   Clone project

        git clone https://github.com/VirgilSecurity/virgil-cli.git

1.   Go to the project's folder.

        cd virgil-cli

1.   Checkout specific branch if needed.

1.   Create folder for the build purposes and go to it

        mkdir build && cd build

1.   Configure, build, and install

        cmake .. && make && make install

1.   Check instalation

        virgil --version


## Windows MSVC Build

### Toolchain
*   [Visual Studio 2015](https://www.visualstudio.com/)
*   [CMake](http://www.cmake.org/) (accessible in command prompt). Minimum version: 3.2.
*   [Git](http://git-scm.com/) (accessible in command prompt).
*   [Python](https://www.python.org/) (accessible in command prompt). Minimum version: 2.7.
*   [Python YAML](http://pyyaml.org/).
*   [NSIS](http://nsis.sourceforge.net/).


### Build steps
1.   Open `Visual Studio Command Prompt`

1.   Clone project

        git clone https://github.com/VirgilSecurity/virgil-cli.git

1.   Go to the project's folder.

        cd virgil-cli

1.   Checkout specific branch if needed.

1.   Create folder for the build purposes and go to it

        md build
        cd build

1.   Configure, build, and make installer

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
