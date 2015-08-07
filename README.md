# Virgil Security CLI

## About

The `virgil`  program  is a command line tool for using Virgil Security stack functionality.
It can be used to encrypt, decrypt, sign and verify data.
Functionality also includes interaction with Virgil Public Keys Service.

## Unix Build

### Toolchain

*   [CMake](http://www.cmake.org/) (accessible in command prompt). Minimum version: 3.0.
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

1. Check instalation

        virgil --version
