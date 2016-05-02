#
# Copyright (C) 2015 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

# Configurable variables:
#     - INSTALL_BIN_DIR_NAME  - name of the directory where binaries will be installed.
#     - INSTALL_MAN_DIR_NAME  - name of the directory where man pages will be installed.
#     - INSTALL_DOC_DIR_NAME  - name of the directory where documentation will be installed.
#
# Define variables:
#     - CLI_VERSION       - CLI full version.
#     - CLI_VERSION_MAJOR - CLI major version number.
#     - CLI_VERSION_MINOR - CLI minor version number.
#     - CLI_VERSION_PATCH - CLI patch number.

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

project (virgil_cli)

# Configure path to custom modules
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

# Define enviroment parameters
include (check_pointer_size)
check_pointer_size (POINTER_SIZE)
if (POINTER_SIZE)
    message (STATUS "Compiler pointer size: " ${POINTER_SIZE} " bytes")
else ()
    message (STATUS "Compiler pointer size: UNDEFINED")
endif ()

# Enable C++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Inspect system
set (SYSTEM_ARCH x86)
if (POINTER_SIZE EQUAL 8)
    set (SYSTEM_ARCH x64)
endif ()
string (TOLOWER "${CMAKE_SYSTEM_NAME}" SYSTEM_NAME)

# Check compiler version
if (MSVC)
    # MSVC14
    if (NOT MSVC_VERSION EQUAL 1900)
        message (FATAL_ERROR "Unsupported MSVC version found. Allowed versions: Visual Studio 2015 (MSVC14)")
    endif (NOT MSVC_VERSION EQUAL 1900)
endif (MSVC)

# Configure path to local libraries
if (MSVC)
    set (EXT_PREBUILD_MSVC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/prebuild/msvc")
    set (CMAKE_PREFIX_PATH "${EXT_PREBUILD_MSVC_DIR}/${SYSTEM_ARCH}/libcurl" ${CMAKE_PREFIX_PATH})
    set (CURL_LIBRARY_DLL "${EXT_PREBUILD_MSVC_DIR}/${SYSTEM_ARCH}/libcurl/lib/libcurl.dll")
endif (MSVC)

# Configure version
set (CLI_VERSION_MAJOR 2)
set (CLI_VERSION_MINOR 0)
set (CLI_VERSION_PATCH 0)
set (CLI_VERSION ${CLI_VERSION_MAJOR}.${CLI_VERSION_MINOR}.${CLI_VERSION_PATCH})
message (STATUS "CLI version: " ${CLI_VERSION})

# Configure path variables
set (INSTALL_BIN_DIR_NAME bin CACHE STRING "Installation directory name for executables")
set (INSTALL_MAN_DIR_NAME "share/man" CACHE STRING "Installation directory name for man pages")

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set (CONFIG_FILE_DIR_NAME "$ENV{HOME}/.config/virgil-cli")
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set (CONFIG_FILE_DIR_NAME "$ENV{HOME}/Library/Application Support/virgil-cli")
else ()
    # win32
endif ()

set (INSTALL_CONFIG_FILE_DIR_NAME ${CONFIG_FILE_DIR_NAME} CACHE STRING "Installation directory name for config file")
message (STATUS "Installation directory name for config file: " ${INSTALL_CONFIG_FILE_DIR_NAME})

set(TOKEN "eyJpZCI6ImM0OWVmOWQ4LWJiNTQtNGY2Zi04NzM0LTFjNDVjNWIxODBlMiIsImFwcGxpY2F0aW9uX2NhcmRfaWQiOiJiMmJlYzNjMS05ZjU0LTQyMDctYTY0Ny00YmE3NDI4MDY2NTMiLCJ0dGwiOi0xLCJjdGwiOi0xLCJwcm9sb25nIjowfQ==.MIGZMA0GCWCGSAFlAwQCAgUABIGHMIGEAkAC4w0Z6XFoGE+4VJk1jJlE3Vtaxwd7qSoEi16PgVaPQ1N/ZQd0hT/fkdueH2X4SYE+dd0Q3AIpMaJYYS56kptqAkAAm/noIrmVmcydoKD5xytXvRKRME5AhL/tifHbpyHnilPP0QhnoLVbUR6lo5uqPt6xzHnEok9omdREhq5wQ0Zx")

# Configure application token
set (VIRGIL_ACCESS_TOKEN ${TOKEN} CACHE STRING
        "Application specific token acquired from the Virgil Security")

if (NOT VIRGIL_ACCESS_TOKEN)
    message (FATAL_ERROR "VIRGIL_ACCESS_TOKEN configuration is not defined.")
endif ()

# Find dependencies
find_package (CURL REQUIRED)
include_directories (${CURL_INCLUDE_DIRS})

include (virgil)
virgil_add_dependency ("crypto"
    VIRGIL_CRYPTO_DEPENDENCIES
    VIRGIL_CRYPTO_INCLUDE_DIRS
    VIRGIL_CRYPTO_LIBRARIES
)
include_directories (${VIRGIL_CRYPTO_INCLUDE_DIRS})

virgil_add_dependency ("virgil-sdk"
    VIRGIL_SDK_DEPENDENCIES
    VIRGIL_SDK_INCLUDE_DIRS
    VIRGIL_SDK_LIBRARIES
)
include_directories (${VIRGIL_SDK_INCLUDE_DIRS})

include (json)
include_directories (${JSON_INCLUDE_DIRS})

if (CMAKE_TOOLCHAIN_FILE)
   list (APPEND CMAKE_ARGS
               -DCMAKE_TOOLCHAIN_FILE:PATH=${CMAKE_TOOLCHAIN_FILE}
)
endif (CMAKE_TOOLCHAIN_FILE)

# Use ext header only libs
include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/ext")
message (STATUS "TCLAP library: ON")

# Use virgil-cli headers
include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/include")

# Grab source directory tree
file (GLOB_RECURSE SRC_LIST "src/*.cxx")
foreach (SRC_FILE ${SRC_LIST})
    string (REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/src/" "" SRC_REL_PATH ${SRC_FILE})
    configure_file (
        "${CMAKE_CURRENT_SOURCE_DIR}/src/${SRC_REL_PATH}"
        "${CMAKE_CURRENT_BINARY_DIR}/src/${SRC_REL_PATH}"
        @ONLY
    )
endforeach ()
file (GLOB_RECURSE SRC_LIST "${CMAKE_CURRENT_BINARY_DIR}/src/*.cxx")

add_executable (virgil_cli ${SRC_LIST})
target_link_libraries (virgil_cli
    ${VIRGIL_SDK_LIBRARIES}
    ${VIRGIL_CRYPTO_LIBRARIES}
    ${CURL_LIBRARIES}
)

add_dependencies (virgil_cli
    json
    ${VIRGIL_CRYPTO_DEPENDENCIES}
    ${VIRGIL_SDK_DEPENDENCIES}
)
set_target_properties (virgil_cli PROPERTIES OUTPUT_NAME "virgil")

# Install virgil_cli
install (TARGETS virgil_cli DESTINATION ${INSTALL_BIN_DIR_NAME})

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    install (
        FILES ${CMAKE_CURRENT_SOURCE_DIR}/data/virgil-cli-config.ini
        DESTINATION ${INSTALL_CONFIG_FILE_DIR_NAME}
    )
    install (DIRECTORY "doc/man/" DESTINATION ${INSTALL_MAN_DIR_NAME})
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    install (
        FILES ${CMAKE_CURRENT_SOURCE_DIR}/data/virgil-cli-config.ini
        DESTINATION ${INSTALL_CONFIG_FILE_DIR_NAME}
    )
    install (DIRECTORY "doc/man/" DESTINATION ${INSTALL_MAN_DIR_NAME})
else ()
    # win32
    if (MSVC)
        install (PROGRAMS "${CURL_LIBRARY_DLL}" DESTINATION "${INSTALL_BIN_DIR_NAME}")
        install (PROGRAMS "${EXT_PREBUILD_MSVC_DIR}/install/vc_redist.${SYSTEM_ARCH}.exe" DESTINATION "install")
        install (PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/data/virgil-cli-config.ini" DESTINATION "install")
    endif (MSVC)
endif ()


# Pack
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "The Virgil Security CLI program is a command line tool for using Virgil Security stack functionality. "
    "It can be used to encrypt, decrypt, sign and verify data. "
    "Functionality also includes interaction with Virgil Public Keys Service and Virgil Private Keys Service."
)

set (CPACK_PACKAGE_NAME "virgil ${CLI_VERSION}-${SYSTEM_ARCH}")
set (CPACK_PACKAGE_VENDOR "Virgil Security Inc")
set (CPACK_PACKAGE_VERSION_MAJOR "${CLI_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${CLI_VERSION_MINOR}")
set (CPACK_PACKAGE_VERSION_PATCH "${CLI_VERSION_PATCH}")
set (CPACK_PACKAGE_FILE_NAME
    "virgil ${CLI_VERSION}-${SYSTEM_ARCH}")

set(CPACK_MONOLITHIC_INSTALL TRUE)

set (CPACK_PACKAGE_INSTALL_DIRECTORY "Virgil Security CLI")
set (CPACK_PACKAGE_INSTALL_REGISTRY_KEY "virgil ${CLI_VERSION_MAJOR}.${CLI_VERSION_MINOR}.${CLI_VERSION_PATCH}-${SYSTEM_NAME}-${SYSTEM_ARCH}")

set (CPACK_PACKAGE_EXECUTABLES "virgil" "virgil-${SYSTEM_ARCH}")
set (CPACK_CREATE_DESKTOP_LINKS "virgil")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

if (MSVC)
    set(CPACK_GENERATOR "NSIS")

    set (CPACK_NSIS_MODIFY_PATH "ON")
    set (CPACK_NSIS_DISPLAY_NAME "Virgil Security CLI")
    set (CPACK_NSIS_CONTACT "support@virgilsecurity.com")

    set (CPACK_NSIS_EXTRA_INSTALL_COMMANDS
        "ExecWait '\\\"$INSTDIR\\\\install\\\\vc_redist.${SYSTEM_ARCH}.exe\\\" /install /quiet'"
        "SetShellVarContext current"
        "CreateDirectory \\\"$APPDATA\\\\virgil-cli\\\""
        "CopyFiles \\\"install\\\\virgil-cli-config.ini\\\" \\\"$APPDATA\\\\virgil-cli\\\""
        "SetShellVarContext all"
    )

    string (REGEX REPLACE ";" "\n" CPACK_NSIS_EXTRA_INSTALL_COMMANDS "${CPACK_NSIS_EXTRA_INSTALL_COMMANDS}")

    set (CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS
        "SetShellVarContext current"
        # Remove config file
        # example C:\Users\John\AppData\Roaming\virgil-cli
        "Delete \\\"$APPDATA\\\\virgil-cli\\\\virgil-cli-config.ini\\\""
        # Remove directory
        "RMDir \\\"$APPDATA\\\\virgil-cli\\\""
        "SetShellVarContext all"
    )

    string (REGEX REPLACE ";" "\n" CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "${CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS}")

endif (MSVC)

INCLUDE(CPack)
