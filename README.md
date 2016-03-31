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
        - [Encrypt and decrypt data](#encrypt-and-decrypt)
        - [Sign and verify data](#sign-and-verify)
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


### Encrypt data

    virgil encrypt -i plain.txt -o plain.txt.enc pubkey:alice-vs/public.key:ForAlice

### Decrypt data

    virgil decrypt -i plain.txt.enc -k alice-vs/private.key -r id:ForAlice

### Sign data

    virgil sign -i plain.txt -o plain.txt.sign -k alice-vs/private.key


### Verify data

    virgil verify -i plain.txt -s plain.txt.sign -r pubkey:alice-vs/public.key


<br>


## Using virgil-cli with committing to services

### Create a Virgil Card

1. Confirming Identity:

        virgil identity-confirm -d email:alice-vs@mailinator.com -o alice-vs/validated-identity.txt

1.  Create a Virgil Card:

        virgil card-create -f alice-vs/validated-identity.txt --public-key alice-vs/public.key -k alice-vs/private.key -o alice-vs/alice-vs.vcard


## Encrypt and decrypt data
1. Encrypt
Encrypt data for Bob identified by email:

        virgil encrypt -i plain.txt -o plain.txt.enc email:bob-vs@mailinator.com

1. Decrypt
Bob decrypts the data on his side:

        virgil decrypt -i plain.txt.enc -k bob-vs/private.key -r vcard:bob-vs/bob-vs.vcard

1.  Encrypt for multiple recipients.
    Encrypt data for Bob and Tom identified by emails:

        virgil encrypt -i plain.txt -o plain.txt.enc email:bob-vs@mailinator.com email:tom-vs@mailinator.com


## Sign and verify
1. Sign. Alice signs data

        virgil sign -i plain.txt -o plain.txt.sign -k alice-vs/private.key

1. Verify. Bob verifies Alice's signature

        virgil verify -i plain.txt -s plain.txt.sign -r email:alice-vs@mailinator.com

## Build Unix

###  Unix toolchain
*   [CMake](http://www.cmake.org/) (accessible in command prompt). Minimum version: 3.2.
*   [Git](http://git-scm.com/) (accessible in command prompt).
*   [Python](https://www.python.org/) (accessible in command prompt). Minimum version: 2.7.
*   [Python YAML](http://pyyaml.org/).
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

1.   Configure, build, and install

        cmake .. && make && make install

1.   Check instalation

        virgil --version


## Build Windows MSVC

### Windows MSVC toolchain
*   [Visual Studio 2015](https://www.visualstudio.com/)
*   [CMake](http://www.cmake.org/) (accessible in command prompt). Minimum version: 3.2.
*   [Git](http://git-scm.com/) (accessible in command prompt).
*   [Python](https://www.python.org/) (accessible in command prompt). Minimum version: 2.7.
*   [Python YAML](http://pyyaml.org/).
*   [NSIS](http://nsis.sourceforge.net/).


### Windows MSVC build steps
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
