#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.12)
project(cecies C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(${PROJECT_NAME}_MAJOR 4)
set(${PROJECT_NAME}_MINOR 0)
set(${PROJECT_NAME}_PATCH 0)
set(${PROJECT_NAME}_VERSION_STRING "${${PROJECT_NAME}_MAJOR}.${${PROJECT_NAME}_MINOR}.${${PROJECT_NAME}_PATCH}")

option(${PROJECT_NAME}_ENABLE_TESTS "Build tests." OFF)
option(${PROJECT_NAME}_ENABLE_PROGRAMS "Build CLI programs." OFF)
option(${PROJECT_NAME}_ENABLE_EXAMPLES "Build example programs." OFF)
option(${PROJECT_NAME}_DLL "Use as a DLL." OFF)
option(${PROJECT_NAME}_BUILD_DLL "Build as a DLL." OFF)
option(${PROJECT_NAME}_PACKAGE "Build the library and package it into a .tar.gz after successfully building." OFF)

if (WIN32)
    include("${CMAKE_CURRENT_LIST_DIR}/cmake/FixWindowsC5105.cmake")
endif ()

if (${${PROJECT_NAME}_BUILD_DLL})
    add_compile_definitions("CECIES_BUILD_DLL=1")
    set(${PROJECT_NAME}_DLL ON)
endif ()

if (${${PROJECT_NAME}_DLL})
    add_compile_definitions("CECIES_DLL=1")
endif ()

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)

set(${PROJECT_NAME}_INCLUDE_DIR
        ${CMAKE_CURRENT_LIST_DIR}/include
        )

set(${PROJECT_NAME}_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/cecies/constants.h
        ${CMAKE_CURRENT_LIST_DIR}/include/cecies/util.h
        ${CMAKE_CURRENT_LIST_DIR}/include/cecies/guid.h
        ${CMAKE_CURRENT_LIST_DIR}/include/cecies/types.h
        ${CMAKE_CURRENT_LIST_DIR}/include/cecies/keygen.h
        ${CMAKE_CURRENT_LIST_DIR}/include/cecies/encrypt.h
        ${CMAKE_CURRENT_LIST_DIR}/include/cecies/decrypt.h
        )

set(${PROJECT_NAME}_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/util.c
        ${CMAKE_CURRENT_LIST_DIR}/src/guid.c
        ${CMAKE_CURRENT_LIST_DIR}/src/keygen.c
        ${CMAKE_CURRENT_LIST_DIR}/src/encrypt.c
        ${CMAKE_CURRENT_LIST_DIR}/src/decrypt.c
        )

add_library(${PROJECT_NAME}
        ${${PROJECT_NAME}_HEADERS}
        ${${PROJECT_NAME}_SOURCES}
        )

if (NOT TARGET mbedtls)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls mbedtls)
endif ()

set(${PROJECT_NAME}_PREV_BUILD_SHARED_LIBS BUILD_SHARED_LIBS)

if (BUILD_SHARED_LIBS)
    set(BUILD_SHARED_LIBS Off)
endif ()

if (NOT TARGET ccrush)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/ccrush ccrush)
endif ()

set_property(TARGET ccrush PROPERTY POSITION_INDEPENDENT_CODE ON)

if (${${PROJECT_NAME}_BUILD_DLL} OR BUILD_SHARED_LIBS)
    set_property(TARGET mbedtls PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedx509 PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedcrypto PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            VERSION ${${PROJECT_NAME}_VERSION_STRING}
            SOVERSION ${${PROJECT_NAME}_MAJOR}
            )
endif ()

if (${${PROJECT_NAME}_PACKAGE})
    set_target_properties(${PROJECT_NAME} PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"

            ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"

            ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            )

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy ${CMAKE_CURRENT_LIST_DIR}/NOTICE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/NOTICE"
            )

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy_directory ${CMAKE_CURRENT_LIST_DIR}/include "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/include"
            )

    string(TOLOWER "${PROJECT_NAME}-${${PROJECT_NAME}_VERSION_STRING}-${CMAKE_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz" ${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME)

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E tar "czvf" ${${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME} ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}
            )
endif ()

target_link_libraries(${PROJECT_NAME}
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto
        PUBLIC ccrush
        )

if ((${CMAKE_SYSTEM_NAME} STREQUAL "Linux") OR (${CYGWIN}))
    target_link_libraries(${PROJECT_NAME} PRIVATE -luuid -lm)
endif ()

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC bcrypt)
endif ()


target_include_directories(${PROJECT_NAME}
        PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/ccrush/include
        )

get_target_property(${PROJECT_NAME}_DEPS_TARGETS ${PROJECT_NAME} LINK_LIBRARIES)

if (${${PROJECT_NAME}_ENABLE_EXAMPLES})
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/examples examples)
endif ()

if (${${PROJECT_NAME}_ENABLE_PROGRAMS})
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/programs programs)
endif ()

if (${${PROJECT_NAME}_ENABLE_TESTS})

    add_executable(run_tests
            ${CMAKE_CURRENT_LIST_DIR}/tests/tests.c
            )

    target_link_libraries(run_tests
            PUBLIC ${PROJECT_NAME}
            PUBLIC ${${PROJECT_NAME}_DEPS_TARGETS}
            )

    target_include_directories(run_tests
            PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
            PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/acutest/include
            PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
            PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/ccrush/include
            )

    if (ENABLE_COVERAGE)
        find_package(codecov)
        add_coverage(${PROJECT_NAME})
        add_coverage(run_tests)
        coverage_evaluate()
    endif ()
endif ()

set(BUILD_SHARED_LIBS ${${PROJECT_NAME}_PREV_BUILD_SHARED_LIBS})