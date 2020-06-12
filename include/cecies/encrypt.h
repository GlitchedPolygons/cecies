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
#define CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_PBKDF2_ITERATIONS 1004

/**
 * Encrypts the given data using ECIES over Curve448 and AES256-GCM.
 * @param data The data to encrypt.
 * @param data_length The length of the data array.
 * @param public_key The public key to encrypt the data with (hex-string format, as is the output of cecies_generate_curve448_keypair()).
 * @param pbkdf2_iterations The amount of PBKDF2 iterations to use for deriving the AES key from the ephemeral key. Pass <c>0</c> to use the default value (which currently is 256k iterations). A value of >100k is recommended, and anything under 32k immediately stops the procedure and returns an error. For safety's sake. Also, very important: keep this value somewhere, as you'll need it inside cecies_decrypt(), where it needs to be **IDENTICAL** in order for decryption to succeed (even despite having the correct private key!).
 * @param output Where to write the encrypted output into (please pre-allocate this big enough, you can use cecies_calc_output_buffer_needed_size() to find out how much you need).
 * @param output_bufsize How big the output buffer is.
 * @param output_length [OPTIONAL] Where to write the output buffer length into (this will be less than the provided output_bufsize). Pass <c>NULL</c> if you don't care (e.g. you already know the output size because you allocated space using cecies_calc_output_buffer_needed_size()).
 * @param output_base64 Should the encrypted output bytes be base64-encoded for easy transmission over e.g. email? If you decide to base64-encode the encrypted data buffer, please be aware that a NUL-terminator is appended at the end to allow usage as a C-string but it will not be counted in \p output_length.
 * @return <c>0</c> if encryption succeeded;  error codes as defined inside the header file or MbedTLS otherwise.
 */
int cecies_encrypt(const unsigned char* data, size_t data_length, const char public_key[114], size_t pbkdf2_iterations, unsigned char* output, size_t output_bufsize, size_t* output_length, bool output_base64);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_ENCRYPT_H
