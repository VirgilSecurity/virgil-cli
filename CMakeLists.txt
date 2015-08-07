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

cmake_minimum_required (VERSION 3.0 FATAL_ERROR)

project (virgil_cli)

# Enable C++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure path to custom modules
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

# Configure version
set (CLI_VERSION_MAJOR 0)
set (CLI_VERSION_MINOR 2)
set (CLI_VERSION_PATCH 0)
set (CLI_VERSION ${CLI_VERSION_MAJOR}.${CLI_VERSION_MINOR}.${CLI_VERSION_PATCH})
message (STATUS "CLI version: " ${CLI_VERSION})

# Configure path variables
set (INSTALL_BIN_DIR_NAME bin CACHE STRING "Installation directory name for executables")
set (INSTALL_MAN_DIR_NAME "share/man" CACHE STRING "Installation directory name for man pages")
set (INSTALL_DOC_DIR_NAME "share/doc" CACHE STRING "Installation directory name for doc pages")

# Configure application token
set (VIRGIL_APP_TOKEN "a9b7434cda37b327bdd075bbde201b5d" CACHE STRING
        "Application specific token acquired from the Virgil Security")

if (NOT VIRGIL_APP_TOKEN)
    message (FATAL_ERROR "VIRGIL_APP_TOKEN configuration is not defined.")
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

virgil_add_dependency ("keys-public"
    VIRGIL_KEYS_PUBLIC_DEPENDENCIES
    VIRGIL_KEYS_PUBLIC_INCLUDE_DIRS
    VIRGIL_KEYS_PUBLIC_LIBRARIES
)
include_directories (${VIRGIL_KEYS_PUBLIC_INCLUDE_DIRS})

# Use tclap lib
include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/ext")
message (STATUS "TCLAP library: ON")

#
include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/include")

# Define sources list
aux_source_directory ("src/common" SRC_LIST)
aux_source_directory ("src/commands" SRC_LIST)

foreach (src_file ${SRC_LIST})
    configure_file (
        "${CMAKE_CURRENT_SOURCE_DIR}/${src_file}"
        "${CMAKE_CURRENT_BINARY_DIR}/${src_file}"
        @ONLY
    )
endforeach ()

aux_source_directory(${CMAKE_CURRENT_BINARY_DIR}/src/common SRC_COMMON)
aux_source_directory(${CMAKE_CURRENT_BINARY_DIR}/src/commands SRC_COMMANDS)

add_executable (virgil_cli ${SRC_COMMON} ${SRC_COMMANDS})
target_link_libraries (virgil_cli ${VIRGIL_CRYPTO_LIBRARIES} ${VIRGIL_KEYS_PUBLIC_LIBRARIES} ${CURL_LIBRARIES})
add_dependencies (virgil_cli ${VIRGIL_CRYPTO_DEPENDENCIES} ${VIRGIL_KEYS_PUBLIC_DEPENDENCIES})
set_target_properties (virgil_cli PROPERTIES OUTPUT_NAME "virgil")

# Install virgil_cli
install (TARGETS virgil_cli DESTINATION ${INSTALL_BIN_DIR_NAME})
if (UNIX)
    install (DIRECTORY "doc/man/" DESTINATION ${INSTALL_MAN_DIR_NAME})
endif (UNIX)
