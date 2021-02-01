/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/**
 *  @file constants.h
 *  @author Raphael Beck
 *  @brief CECIES constants.
 */

#ifndef CECIES_CONSTANTS_H
#define CECIES_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The version number of this CECIES implementation.
 * TODO: increase this and below string version accordingly BEFORE releasing new updates!
 */
#define CECIES_VERSION 400

/**
 * The version number of this CECIES implementation (nicely-formatted string).
 */
#define CECIES_VERSION_STR "4.0.0"

/**
 * Key size (in bytes) of an X25519 key (both public and private key have the same length).
 */
#define CECIES_X25519_KEY_SIZE 32

/**
 * Key size (in bytes) of an X448 key (both public and private key have the same length).
 */
#define CECIES_X448_KEY_SIZE 56

/*
 * Some error codes:
 */

#define CECIES_ENCRYPT_ERROR_CODE_NULL_ARG 1000
#define CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG 1001
#define CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE 1002
#define CECIES_ENCRYPT_ERROR_CODE_OUT_OF_MEMORY 1003
#define CECIES_ENCRYPT_ERROR_CODE_COMPRESSION_FAILED 1004

#define CECIES_DECRYPT_ERROR_CODE_NULL_ARG 2000
#define CECIES_DECRYPT_ERROR_CODE_INVALID_ARG 2001
#define CECIES_DECRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE 2002
#define CECIES_DECRYPT_ERROR_CODE_OUT_OF_MEMORY 2003

#define CECIES_KEYGEN_ERROR_CODE_NULL_ARG 7000
#define CECIES_KEYGEN_ERROR_CODE_INVALID_ARG 7001

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_CONSTANTS_H
