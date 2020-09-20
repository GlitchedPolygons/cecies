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

set(CECIES_MAJOR 2)
set(CECIES_MINOR 1)
set(CECIES_PATCH 3)

option(CECIES_ENABLE_TESTS "Build CECIES tests." OFF)
option(CECIES_ENABLE_PROGRAMS "Build CECIES CLI programs." OFF)
option(CECIES_ENABLE_EXAMPLES "Build CECIES example programs." OFF)
option(CECIES_DLL "Use CECIES as a DLL." OFF)
option(CECIES_BUILD_DLL "Build CECIES as a DLL." OFF)

if (CECIES_BUILD_DLL)
    add_compile_definitions("CECIES_BUILD_DLL=1")
    set(CECIES_DLL ON)
endif ()

if (CECIES_DLL)
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

if (NOT TARGET mbedtls)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls mbedtls)
endif ()

add_library(${PROJECT_NAME}
        ${${PROJECT_NAME}_HEADERS}
        ${${PROJECT_NAME}_SOURCES}
        )

if (CECIES_BUILD_DLL OR BUILD_SHARED_LIBS)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            VERSION ${CECIES_MAJOR}.${CECIES_MINOR}.${CECIES_PATCH}
            SOVERSION ${CECIES_MAJOR}
    )
endif ()

target_link_libraries(${PROJECT_NAME}
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto
        )

if (UNIX AND NOT APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE -luuid -lm)
endif ()

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC bcrypt)
endif ()

target_include_directories(${PROJECT_NAME}
        PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
        )

get_target_property(${PROJECT_NAME}_DEPS_TARGETS ${PROJECT_NAME} LINK_LIBRARIES)

if (CECIES_ENABLE_EXAMPLES)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/examples examples)
endif ()

if (CECIES_ENABLE_PROGRAMS)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/programs programs)
endif ()

if (CECIES_ENABLE_TESTS)

    find_package(cmocka)

    if (NOT ${cmocka_FOUND})
        message(STATUS "cmocka not found; using included version inside lib/cmocka/ folder...")
        add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/cmocka cmocka)
    else ()
        message(STATUS "Found cmocka!")
    endif ()

    add_executable(run_tests
            ${CMAKE_CURRENT_LIST_DIR}/tests/tests.c
            ${${PROJECT_NAME}_HEADERS}
            ${${PROJECT_NAME}_SOURCES}
            )

    target_include_directories(run_tests
            PUBLIC ${cmocka_INCLUDE_DIR}
            PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
            PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
            )

    target_link_libraries(run_tests
            PUBLIC ${${PROJECT_NAME}_DEPS_TARGETS}
            PUBLIC cmocka
            )

    if (ENABLE_COVERAGE)
        find_package(codecov)
        add_coverage(${PROJECT_NAME})
        add_coverage(run_tests)
        coverage_evaluate()
    endif ()
endif ()
