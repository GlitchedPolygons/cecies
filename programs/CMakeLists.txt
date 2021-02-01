#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.1)
set(CMAKE_C_STANDARD 11)
project(cecies_programs C)

add_compile_definitions(SODIUM_STATIC=1)
add_compile_definitions(CONFIGURED=1)

add_executable(curve25519_keygen ${CMAKE_CURRENT_LIST_DIR}/curve25519_keygen.c)
target_link_libraries(curve25519_keygen PRIVATE cecies)
target_include_directories(curve25519_keygen PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

add_executable(curve448_keygen ${CMAKE_CURRENT_LIST_DIR}/curve448_keygen.c)
target_link_libraries(curve448_keygen PRIVATE cecies)
target_include_directories(curve448_keygen PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

add_executable(secp256k1_keygen ${CMAKE_CURRENT_LIST_DIR}/secp256k1_keygen.c)
target_link_libraries(secp256k1_keygen PRIVATE cecies)
target_include_directories(secp256k1_keygen PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

add_executable(cecies_curve25519_encrypt ${CMAKE_CURRENT_LIST_DIR}/cecies_curve25519_encrypt.c)
target_link_libraries(cecies_curve25519_encrypt PRIVATE cecies)
target_include_directories(cecies_curve25519_encrypt PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

add_executable(cecies_curve25519_decrypt ${CMAKE_CURRENT_LIST_DIR}/cecies_curve25519_decrypt.c)
target_link_libraries(cecies_curve25519_decrypt PRIVATE cecies)
target_include_directories(cecies_curve25519_decrypt PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

add_executable(cecies_curve448_encrypt ${CMAKE_CURRENT_LIST_DIR}/cecies_curve448_encrypt.c)
target_link_libraries(cecies_curve448_encrypt PRIVATE cecies)
target_include_directories(cecies_curve448_encrypt PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

add_executable(cecies_curve448_decrypt ${CMAKE_CURRENT_LIST_DIR}/cecies_curve448_decrypt.c)
target_link_libraries(cecies_curve448_decrypt PRIVATE cecies)
target_include_directories(cecies_curve448_decrypt PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

add_executable(ecdsa_sha256_secp256k1_sign ${CMAKE_CURRENT_LIST_DIR}/ecdsa_sha256_secp256k1_sign.c)
target_link_libraries(ecdsa_sha256_secp256k1_sign PRIVATE cecies)
target_include_directories(ecdsa_sha256_secp256k1_sign PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

add_executable(ecdsa_sha256_secp256k1_verify ${CMAKE_CURRENT_LIST_DIR}/ecdsa_sha256_secp256k1_verify.c)
target_link_libraries(ecdsa_sha256_secp256k1_verify PRIVATE cecies)
target_include_directories(ecdsa_sha256_secp256k1_verify PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

set(ED25519_INC ${CMAKE_CURRENT_LIST_DIR}/../lib/libsodium/src/libsodium/include ${CMAKE_CURRENT_LIST_DIR}/../lib/libsodium/src/libsodium/include/sodium)
file(GLOB_RECURSE ED25519_SRC ${CMAKE_CURRENT_LIST_DIR}/../lib/libsodium/src/libsodium/*.c)
file(GLOB_RECURSE ED25519_HEADERS ${CMAKE_CURRENT_LIST_DIR}/../lib/libsodium/src/libsodium/*.h)

message(STATUS ${ED25519_SRC})
message(STATUS ${ED25519_HEADERS})

add_executable(ed25519_keygen ${CMAKE_CURRENT_LIST_DIR}/ed25519_keygen.c ${ED25519_SRC})
target_link_libraries(ed25519_keygen PRIVATE cecies)
target_include_directories(ed25519_keygen PRIVATE ${ED25519_INC})
target_include_directories(ed25519_keygen PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

add_executable(ed25519_sign ${CMAKE_CURRENT_LIST_DIR}/ed25519_sign.c ${ED25519_SRC})
target_link_libraries(ed25519_sign PRIVATE cecies)
target_include_directories(ed25519_sign PRIVATE ${ED25519_INC})
target_include_directories(ed25519_sign PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)

add_executable(ed25519_verify ${CMAKE_CURRENT_LIST_DIR}/ed25519_verify.c ${ED25519_SRC})
target_link_libraries(ed25519_verify PRIVATE cecies)
target_include_directories(ed25519_verify PRIVATE ${ED25519_INC})
target_include_directories(ed25519_verify PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)
