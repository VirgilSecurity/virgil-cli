[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-cli.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-cli)

# Virgil Security CLI

- [Motivation](#motivation)
- [Quickstart](#quickstart)
    - [Generate Keys](#generate-keys)
    - [Encrypt data](#encrypt-data)
    - [Decrypt data](#decrypt-data)
    - [Sign data](#sign-data)
    - [Verify data](#verify-data)
- [Build: Unix](#build-unix)
    - [Toolchain](#unix-toolchain)
    - [Build steps](#unix-build-steps)
- [Build: Windows MSVC](#build-windows-msvc)
    - [Toolchain](#windows-msvc-toolchain)
    - [Build steps](#windows-msvc-build-steps)
- [Manuals](#manuals)
- [License](#license)
- [Contacts](#contacts)


## Motivation
The **virgil** program is a command line tool for using Virgil Security
stack functionality:

-   encrypt, decrypt, sign and verify data;
-   interact with Virgil Keys Service;
-   interact with Virgil Private Keys Service.


## Quickstart

## Generate Keys
Generate Elliptic Curve Private Key or RSA Private Key.

1.  Generate Elliptic 512-bits Brainpool Curve Private Key(default):

        virgil keygen -o private.key

2.  Generate Elliptic Curve Private Key with password protection:

        virgil keygen -o private.key -p

3.  Generate Elliptic 521-bits NIST Curve Private Key:

        virgil keygen -o private.key -e secp521r1

4.  Generate RSA Private Key:

        virgil keygen -r rsa8192 -o private.key


## Encrypt data
Encrypt data for given recipients. Recipient can be represented either
by the password, or by the Virgil Public Key.

1.  Encrypt data for Bob identified by email:

        virgil encrypt -i plain.txt -o plain.txt.enc email:bob@domain.com

2.  Encrypt data for Bob and Tom identified by emails:

        virgil encrypt -i plain.txt -o plain.txt.enc email:bob@domain.com email:tom@domain.com

3.  Encrypt data for user identified by password:

        virgil encrypt -i plain.txt -o plain.txt.enc pass:strong_password


## Decrypt data
Decrypt data with given password or given Private Key.

1.  Decrypt data for user identified by email:

        virgil decrypt -i plain.txt.enc -o plain.txt -k private.key -r email:user@domain.com

2.  Decrypt data for user identified by password:

        virgil decrypt -i plain.txt.enc -o plain.txt -k private.key -r pass:strong_password


## Sign data
Sign data with given user's Private Key.

        virgil sign -i plain.txt -o plain.txt.sign -k private.key


## Verify data
Verify data and signature with given user's identifier or with it Virgil
Public Key.

        virgil verify -i plain.txt -s plain.txt.sign -e email:user@domain.com


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
See manual pages [here](https://github.com/VirgilSecurity/virgil-cli/blob/v1.0.0/doc/markdown/virgil.1.md).


## License
BSD 3-Clause. See [LICENSE](https://github.com/VirgilSecurity/virgil-cli/blob/master/LICENSE) for details.


## Contacts
Email: <support@virgilsecurity.com>
