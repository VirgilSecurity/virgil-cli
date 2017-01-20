#
# Copyright (C) 2016 Virgil Security Inc.
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
#     - INSTALL_LIB_DIR_NAME  - name of the directory where libraries will be installed.
#     - INSTALL_MAN_DIR_NAME  - name of the directory where man pages will be installed.
#     - INSTALL_DOC_DIR_NAME  - name of the directory where documentation will be installed.
#     - INSTALL_CFG_DIR_PATH  - path to the directory where configurations will be installed.
#
#     - CLI_APPLICATION_TOKEN - unique value that provides an authenticated secure access to the Virgil services.
#
# Define variables:
#     - VIRGIL_CLI_VERSION_MAJOR         - major version number.
#     - VIRGIL_CLI_VERSION_MINOR         - minor version number.
#     - VIRGIL_CLI_VERSION_PATCH         - patch number.
#     - VIRGIL_CLI_VERSION_FEATURE       - version feature, i.e. alpha, beta, rc1, etc.
#     - VIRGIL_CLI_VERSION               - full version.
#
#     - CFG_DIR_PATH - path to the directory where configurations is installed.

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

project (virgil_cli VERSION 3.0.0)

# Enable C++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure path to custom modules
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

# Include helpers
include (virgil_log)

# Define version info
set (VIRGIL_CLI_VERSION_MAJOR ${virgil_cli_VERSION_MAJOR})
set (VIRGIL_CLI_VERSION_MINOR ${virgil_cli_VERSION_MINOR})
set (VIRGIL_CLI_VERSION_PATCH ${virgil_cli_VERSION_PATCH})
set (VIRGIL_CLI_VERSION_FEATURE "dev")

if (VIRGIL_CLI_VERSION_FEATURE)
    set (VIRGIL_CLI_VERSION ${virgil_cli_VERSION}-${VIRGIL_CLI_VERSION_FEATURE})
else (VIRGIL_CLI_VERSION_FEATURE)
    set (VIRGIL_CLI_VERSION ${virgil_cli_VERSION})
endif (VIRGIL_CLI_VERSION_FEATURE)

# Configurable variables
## Installation directories
set (INSTALL_BIN_DIR_NAME bin CACHE STRING "Installation directory name for executables")
set (INSTALL_LIB_DIR_NAME lib CACHE STRING "Installation directory name for libraries")
set (INSTALL_MAN_DIR_NAME "share/man" CACHE STRING "Installation directory name for man pages")
set (INSTALL_CFG_DIR_NAME ".virgil/conf" CACHE PATH "Installation directory path for system configuration files")
set (INSTALL_LOG_DIR_NAME ".virgil/log" CACHE PATH "Installation directory path for log fles")

# Configure application token
set (VIRGIL_ACCESS_TOKEN ${TOKEN} CACHE STRING
        "Application specific token acquired from the Virgil Security")

## Crosscompiling
set (UCLIBC OFF CACHE BOOL "Enable pathches if CLI is build with uClibc++")

## Compiler specific configuration
set (USE_BOOST_REGEX OFF CACHE BOOL "Use Boost::regex instead of std::regex")

## Link with shared library if defined
set (BUILD_SHARED_LIBS OFF CACHE BOOL "Force to link with shared libraries")

## Virgil service
if (CLI_APPLICATION_TOKEN)
    set (CLI_APPLICATION_TOKEN "${CLI_APPLICATION_TOKEN}" CACHE STRING
         "Unique value that provides an authenticated secure access to the Virgil services" FORCE)
else ()
    virgil_log_error ("CLI_APPLICATION_TOKEN is not defined.")
endif ()

# Define enviroment parameters
if (CMAKE_SIZEOF_VOID_P)
    virgil_log_info ("Compiler pointer size: ${CMAKE_SIZEOF_VOID_P} bytes")
else ()
    virgil_log_info ("Compiler pointer size: UNDEFINED")
endif ()

# Inspect system
set (SYSTEM_ARCH x86)
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set (SYSTEM_ARCH x64)
endif ()
string (TOLOWER "${CMAKE_SYSTEM_NAME}" SYSTEM_NAME)

if (WIN32 AND NOT CYGWIN)
    set (OS_WIN32 1)
else ()
    set (OS_WIN32 0)
endif ()

if (UNIX)
    set (OS_UNIX 1)
else ()
    set (OS_UNIX 0)
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set (OS_DARWIN 1)
else ()
    set (OS_DARWIN 0)
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    set (OS_LINUX 1)
else ()
    set (OS_LINUX 0)
endif ()

# Check compiler version
if (MSVC)
    # MSVC14
    if (MSVC_VERSION LESS 1900)
        virgil_log_error ("Unsupported MSVC version found. Allowed versions greater then Visual Studio 2015 (MSVC14)")
    endif (MSVC_VERSION LESS 1900)
endif (MSVC)

# Configure path to local libraries
if (MSVC)
    set (EXT_PREBUILD_MSVC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/prebuild/msvc")
    set (CMAKE_PREFIX_PATH "${EXT_PREBUILD_MSVC_DIR}/${SYSTEM_ARCH}/libcurl" ${CMAKE_PREFIX_PATH})
    set (CURL_LIBRARY_DLL "${EXT_PREBUILD_MSVC_DIR}/${SYSTEM_ARCH}/libcurl/lib/libcurl.dll")
    file (COPY "${CURL_LIBRARY_DLL}"
        DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
    )
endif (MSVC)

if (UNIX)
    if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        # Use relative to executable RPATH for OS X
        set (CMAKE_INSTALL_NAME_DIR "@executable_path/../lib")
    else ()
        # Use full RPATH for all UNIX systems except OS X, see https://cmake.org/Wiki/CMake_RPATH_handling
        set (CMAKE_SKIP_BUILD_RPATH  FALSE)
        set (CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
        set (CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${INSTALL_LIB_DIR_NAME}")
        set (CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    endif ()
endif ()

# Add system external dependencies
find_package (CURL REQUIRED)
find_package(Threads REQUIRED)
if (USE_BOOST_REGEX)
    find_package(Boost 1.53 REQUIRED COMPONENTS regex)
    if (NOT Boost_FOUND)
        virgil_log_error("USE_BOOST_REGEX defined but boost is not found.")
    endif()
endif ()
# Add in-house external dependencies
include (virgil_depends)

virgil_depends (
    PACKAGE_NAME "virgil_sdk"
    CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/virgil_sdk"
)
virgil_find_package (virgil_sdk)
virgil_find_package (virgil_crypto)
virgil_find_package (nlohman_json)
virgil_find_package (restless)
virgil_find_package (mbedtls)
virgil_find_package (tinyformat)

virgil_depends (
    PACKAGE_NAME "easylogging"
    CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/easylogging"
)
virgil_find_package (easylogging)

virgil_depends (
    PACKAGE_NAME "docopt"
    CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/docopt"
)
virgil_find_package (docopt)

virgil_depends (
    PACKAGE_NAME "yaml-cpp"
    CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/yaml-cpp"
)
virgil_find_package (yaml-cpp)

# Show versions info
virgil_log_info ("Found Virgil CLI, version " ${VIRGIL_CLI_VERSION})
virgil_log_info ("Found Virgil SDK, version " ${virgil_sdk_VERSION})
virgil_log_info ("Found Virgil Crypto, version " ${virgil_crypto_VERSION})
virgil_log_info ("Found Easy Logging++, version " ${easylogging_VERSION})
virgil_log_info ("Found DocOpt, version " ${docopt_VERSION})
virgil_log_info ("Found TinyFormat, version " ${tinyformat_VERSION})
virgil_log_info ("Found YAML, version " ${yaml_cpp_VERSION})

# Define variables that is used in the source files
file (READ "${CMAKE_CURRENT_SOURCE_DIR}/conf/default-config.yaml" CLI_DEFAULT_CONFIG_CONTENT)

# Grab source directory tree
file (GLOB_RECURSE INC_SRC_LIST "src/*.cxx.in")
foreach (SRC_FILE ${INC_SRC_LIST})
    string (REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/src/" "" SRC_REL_PATH ${SRC_FILE})
    string (REPLACE ".in" "" SRC_REL_PATH ${SRC_REL_PATH})
    configure_file (
            "${CMAKE_CURRENT_SOURCE_DIR}/src/${SRC_REL_PATH}.in"
            "${CMAKE_CURRENT_BINARY_DIR}/src/${SRC_REL_PATH}"
            @ONLY
    )
endforeach ()
file (GLOB_RECURSE BIN_SRC_LIST "${CMAKE_CURRENT_BINARY_DIR}/src/*.cxx")
file (GLOB_RECURSE SRC_SRC_LIST "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cxx")
set (SRC_LIST ${BIN_SRC_LIST} ${SRC_SRC_LIST})

add_executable (virgil_cli ${SRC_LIST})
target_include_directories (virgil_cli PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/ext"
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CURL_INCLUDE_DIRS}"
        )
target_link_libraries (virgil_cli
                       virgil::security::virgil_sdk
                       docopt_s
                       yaml-cpp
                       ${CURL_LIBRARIES}
                       ${Boost_LIBRARIES}
                       Threads::Threads
                       )
set_target_properties (virgil_cli PROPERTIES OUTPUT_NAME "virgil")

# Install shared libraries
if (BUILD_SHARED_LIBS)
    install (DIRECTORY "${VIRGIL_DEPENDS_PREFIX}/lib/" DESTINATION "${INSTALL_LIB_DIR_NAME}"
        PATTERN "cmake" EXCLUDE
        PATTERN "pkgconfig" EXCLUDE
    )
endif ()

# Install virgil_cli
install (TARGETS virgil_cli
    RUNTIME DESTINATION ${INSTALL_BIN_DIR_NAME}
    LIBRARY DESTINATION ${INSTALL_LIB_DIR_NAME}
)

if (UNIX)
#     install (DIRECTORY "doc/man/" DESTINATION "${INSTALL_MAN_DIR_NAME}")
elseif (WIN32 AND NOT CYGWIN)
    install (PROGRAMS "${CURL_LIBRARY_DLL}" DESTINATION "${INSTALL_BIN_DIR_NAME}")
    if (MSVC)
        install (PROGRAMS "${EXT_PREBUILD_MSVC_DIR}/install/vc_redist.${SYSTEM_ARCH}.exe" DESTINATION "install")
    endif (MSVC)
endif ()

# Format code
add_custom_target(format
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/utils/format_code.sh"
)

# Pack
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY
     "The Virgil Security CLI program is a command line tool for using Virgil Security stack functionality. "
     "It can be used to encrypt, decrypt, sign and verify data. "
     "Functionality also includes interaction with Virgil Public Keys Service and Virgil Private Keys Service."
     )

set (CPACK_PACKAGE_NAME "virgil-${VIRGIL_CLI_VERSION}-${SYSTEM_ARCH}")
set (CPACK_PACKAGE_VENDOR "Virgil Security Inc")
set (CPACK_PACKAGE_VERSION_MAJOR "${VIRGIL_CLI_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${VIRGIL_CLI_VERSION_MINOR}")
set (CPACK_PACKAGE_VERSION_PATCH "${VIRGIL_CLI_VERSION_PATCH}")
set (CPACK_PACKAGE_VERSION "${VIRGIL_CLI_VERSION}")

set (CPACK_PACKAGE_FILE_NAME
     "virgil-${VIRGIL_CLI_VERSION}-${SYSTEM_ARCH}")

set(CPACK_MONOLITHIC_INSTALL TRUE)

set (CPACK_PACKAGE_INSTALL_DIRECTORY "Virgil Security CLI")
set (CPACK_PACKAGE_INSTALL_REGISTRY_KEY
     "virgil-${VIRGIL_CLI_VERSION}-${SYSTEM_NAME}-${SYSTEM_ARCH}")

set (CPACK_PACKAGE_EXECUTABLES "virgil" "virgil-${SYSTEM_ARCH}")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

if (MSVC)
    set(CPACK_GENERATOR "NSIS")

    set (CPACK_NSIS_MODIFY_PATH "ON")
    set (CPACK_NSIS_DISPLAY_NAME "Virgil Security CLI")
    set (CPACK_NSIS_CONTACT "support@virgilsecurity.com")

    set (CPACK_NSIS_EXTRA_INSTALL_COMMANDS
         "ExecWait '\\\"$INSTDIR\\\\install\\\\vc_redist.${SYSTEM_ARCH}.exe\\\" /install /quiet'"

         "Push \\\$R0"
         "ExpandEnvStrings \\\$R0 '%COMSPEC%'"
         "CreateShortCut \\\"$SMPROGRAMS\\\\Virgil Security CLI\\\\virgil-${SYSTEM_ARCH}.lnk\\\" \\\"$R0\\\"  \\\"/k set PATH=$INSTDIR\\\\bin\\\""
         "CreateShortCut \\\"$DESKTOP\\\\virgil-${SYSTEM_ARCH}.lnk\\\" \\\"$R0\\\"  \\\"/k set PATH=$INSTDIR\\\\bin\\\""
         )

    string (REGEX REPLACE ";" "\n" CPACK_NSIS_EXTRA_INSTALL_COMMANDS "${CPACK_NSIS_EXTRA_INSTALL_COMMANDS}")

    set (CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS
         "Delete \\\"$SMPROGRAMS\\\\Virgil Security CLI\\\\virgil.lnk\\\""
         "Delete \\\"$DESKTOP\\\\virgil-${SYSTEM_ARCH}.lnk\\\""
         )

    string (REGEX REPLACE ";" "\n" CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "${CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS}")

endif (MSVC)

include (CPack)
