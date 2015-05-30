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

# An extrenal project for Virgil Crypto library build
#
# Define variables:
#     - VIRGIL_LIBRARY_NAME - library file name
#     - VIRGIL_INCLUDE_DIR  - full path to the library includes
#     - VIRGIL_LIBRARY      - full patch to the library
#

include(CheckCCompilerFlag)

if (NOT CMAKE_CROSSCOMPILING)
    # Configure compiler settings
    check_c_compiler_flag (-fPIC COMPILER_SUPPORT_PIC)
    if (COMPILER_SUPPORT_PIC)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    endif()
endif (NOT CMAKE_CROSSCOMPILING)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin" AND CMAKE_OSX_ARCHITECTURES)
    foreach (arch ${CMAKE_OSX_ARCHITECTURES})
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -arch ${arch}")
    endforeach (arch)
endif ()

# Add external project build steps
set (CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    -DLIB_LOW_LEVEL_API:BOOL=ON
    -DLIB_FILE_IO:BOOL=ON
    -DENABLE_TESTING:BOOL=OFF
)

if (CMAKE_TOOLCHAIN_FILE)
    list (APPEND CMAKE_ARGS
        -DCMAKE_TOOLCHAIN_FILE:PATH=${CMAKE_TOOLCHAIN_FILE}
    )
else ()
    list (APPEND CMAKE_ARGS
        -DCMAKE_CXX_COMPILER:STRING=${CMAKE_CXX_COMPILER}
        -DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS}
        -DCMAKE_CXX_FLAGS_RELEASE:STRING=${CMAKE_CXX_FLAGS_RELEASE}
        -DCMAKE_CXX_FLAGS_DEBUG:STRING=${CMAKE_CXX_FLAGS_DEBUG}
    )
endif ()

ExternalProject_Add (virgil_project
    GIT_REPOSITORY "https://github.com/VirgilSecurity/virgil.git"
    GIT_TAG "v0.9.0"
    PREFIX "${CMAKE_CURRENT_BINARY_DIR}/ext/virgil"
    CMAKE_ARGS ${CMAKE_ARGS}
)

# Payload targets and output variables
ExternalProject_Get_Property (virgil_project INSTALL_DIR)

set (VIRGIL_LIBRARY_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}virgil${CMAKE_STATIC_LIBRARY_SUFFIX})
set (MBEDTLS_LIBRARY_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}mbedtls${CMAKE_STATIC_LIBRARY_SUFFIX})
set (JSONCPP_LIBRARY_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}jsoncpp${CMAKE_STATIC_LIBRARY_SUFFIX})
set (VIRGIL_INCLUDE_DIR "${INSTALL_DIR}/include")
set (VIRGIL_LIBRARY "${INSTALL_DIR}/lib/${VIRGIL_LIBRARY_NAME}")
set (VIRGIL_EXT_LIBRARIES "${INSTALL_DIR}/lib/${MBEDTLS_LIBRARY_NAME}")
set (VIRGIL virgil)

# Workaround of http://public.kitware.com/Bug/view.php?id=14495
file (MAKE_DIRECTORY ${VIRGIL_INCLUDE_DIR})

add_library (${VIRGIL} STATIC IMPORTED)
set_property (TARGET ${VIRGIL} PROPERTY IMPORTED_LOCATION ${VIRGIL_LIBRARY})
set_property (TARGET ${VIRGIL} PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${VIRGIL_INCLUDE_DIR})
add_dependencies (${VIRGIL} virgil_project)
