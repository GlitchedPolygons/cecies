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
 *  @file encrypt.h
 *  @author Raphael Beck
 *  @brief ECIES encryption implementation using Curve448, AES256-GCM and MbedTLS.
 */

#ifndef CECIES_ENCRYPT_H
#define CECIES_ENCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define CECIES_ENCRYPT_ERROR_CODE_NULL_ARG 1000
#define CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG 1001
#define CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE 1002
#define CECIES_ENCRYPT_ERROR_CODE_OUT_OF_MEMORY 1003

/**
 * Encrypts the given data using ECIES over Curve448 and AES256-GCM.
 * @param data The data to encrypt.
 * @param data_length The length of the data array.
 * @param public_key The public key to encrypt the data with.
 * @param public_key_length Length of the public_key string.
 * @param public_key_base64 Is the \p public_key base64-formatted? If this is false, the key will be directly fed into mbedtls_ecp_point_read_binary()!
 * @param output Where to write the encrypted output into (please pre-allocate this big enough).
 * @param output_bufsize How big the output buffer is.
 * @param output_length Where to write the output buffer length into (this will be less than the provided output_bufsize).
 * @param output_base64 Should the encrypted output bytes be base64-encoded for easy transmission over e.g. email? If you decide to base64-encode the encrypted data buffer, please be aware that a NUL-terminator is appended at the end to allow usage as a C-string but it will not be counted in \p output_length.
 * @return <c>0</c> if encryption succeeded;  error codes as defined inside the header file or MbedTLS otherwise.
 */
int cecies_encrypt(const unsigned char* data, size_t data_length, const unsigned char* public_key, size_t public_key_length, bool public_key_base64, unsigned char* output, size_t output_bufsize, size_t* output_length, bool output_base64);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_ENCRYPT_H
