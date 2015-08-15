[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-cli.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-cli)

# Virgil Security CLI

- [About](#about)
- [Build: Unix](#build-unix)
    - [Toolchain](#unix-toolchain)
    - [Build steps](#unix-build-steps)
- [Build: Windows MSVC](#build-windows-msvc)
    - [Toolchain](#windows-msvc-toolchain)
    - [Build steps](#windows-msvc-build-steps)
- [License](#license)
- [Contacts](#contacts)

## About

The `virgil`  program  is a command line tool for using Virgil Security stack functionality.
It can be used to encrypt, decrypt, sign and verify data.
Functionality also includes interaction with Virgil Public Keys Service.

## <a name="build-unix"></a> Unix Build

### <a name="unix-toolchain"></a> Toolchain

*   [CMake](http://www.cmake.org/) (accessible in command prompt). Minimum version: 3.2.
*   [Git](http://git-scm.com/) (accessible in command prompt).
*   [Python](https://www.python.org/) (accessible in command prompt). Minimum version: 2.7.
*   [Python YAML](http://pyyaml.org/).
*   [libcurl](http://curl.haxx.se/libcurl/).

### <a name="unix-build-steps"></a> Build steps

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

## <a name="build-windows-msvc"></a> Windows MSVC Build

### <a name="windows-msvc-toolchain"></a> Toolchain

*   [Visual Studio 2015](https://www.visualstudio.com/)
*   [CMake](http://www.cmake.org/) (accessible in command prompt). Minimum version: 3.2.
*   [Git](http://git-scm.com/) (accessible in command prompt).
*   [Python](https://www.python.org/) (accessible in command prompt). Minimum version: 2.7.
*   [Python YAML](http://pyyaml.org/).
*   [NSIS](http://nsis.sourceforge.net/).

### <a name="windows-msvc-build-steps"></a> Build steps

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

## License
BSD 3-Clause. See [LICENSE](https://github.com/VirgilSecurity/virgil-cli/blob/master/LICENSE) for details.

## Contacts
Email: <support@virgilsecurity.com>
