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
 *  @file util.h
 *  @author Raphael Beck
 *  @brief Useful utility functions for CECIES.
 */

#ifndef CECIES_UTIL_H
#define CECIES_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "types.h"
#include "constants.h"

/**
 * <c>x < y ? x : y</c>
 */
#define CECIES_MIN(x, y) (((x) < (y)) ? (x) : (y))

/**
 * <c>x > y ? x : y</c>
 */
#define CECIES_MAX(x, y) (((x) > (y)) ? (x) : (y))

/**
 * Calculates the length of an AES-CBC ciphertext given a specific plaintext data length (in bytes).
 * @param plaintext_length The amount of bytes to encrypt.
 * @return The ciphertext length (a multiple of the blocksize).
 */
static inline size_t cecies_calc_aes_cbc_ciphertext_length(const size_t plaintext_length)
{
    return plaintext_length + 16 - (plaintext_length % 16);
}

/**
 * Gets the minimum amount of needed buffer size for an encryption with a given plaintext data length.
 * @param input_buffer_length The amount of bytes to encrypt.
 * @param key_size Size in bytes of the used ephemeral key (X448 keys are slightly bigger than X25519).
 * @return The min. buffer size for encrypting \p input_buffer_length bytes of data.
 */
static inline size_t cecies_calc_output_buffer_needed_size(const size_t input_buffer_length, const size_t key_size)
{
    //     1    2    3          4
    return 16 + 32 + key_size + 16 + input_buffer_length;

    // 1:  IV (AES initialization vector)
    // 2:  Salt (for HKDF)
    // 3:  R (ephemeral public key)
    // 4:  Tag (from AES-GCM)
}

/**
 * Gets the minimum amount of needed buffer size for a given Curve25519 encryption with a given plaintext data length.
 * @param input_buffer_length The amount of bytes to encrypt.
 * @return The min. buffer size for encrypting \p input_buffer_length bytes of data.
 */
static inline size_t cecies_curve25519_calc_output_buffer_needed_size(const size_t input_buffer_length)
{
    return cecies_calc_output_buffer_needed_size(input_buffer_length, CECIES_X25519_KEY_SIZE);
}

/**
 * Gets the minimum amount of needed buffer size for a given Curve448 encryption with a given plaintext data length.
 * @param input_buffer_length The amount of bytes to encrypt.
 * @return The min. buffer size for encrypting \p input_buffer_length bytes of data.
 */
static inline size_t cecies_curve448_calc_output_buffer_needed_size(const size_t input_buffer_length)
{
    return cecies_calc_output_buffer_needed_size(input_buffer_length, CECIES_X448_KEY_SIZE);
}

/**
 * Calculates the output length in bytes after base64-encoding \p data_length bytes (includes +1 for a NUL-terminator character)..
 * @param data_length The number of bytes you'd base64-encode.
 * @return <c>((4 * data_length / 3 + 3) & ~3) + 1</c>
 */
static inline size_t cecies_calc_base64_length(const size_t data_length)
{
    return ((4 * data_length / 3 + 3) & ~(unsigned)3) + 1;
}

/**
 * Converts a hex string to binary array. <p>
 * A NUL-terminator is appended at the end of the output buffer, so make sure to allocate at least <c>(hexstr_length / 2) + 1</c> bytes!
 * @param hexstr The hex string to convert.
 * @param hexstr_length Length of the \p hexstr
 * @param output Where to write the converted binary data into.
 * @param output_size Size of the output buffer (make sure to allocate at least <c>(hexstr_length / 2) + 1</c> bytes!).
 * @param output_length [OPTIONAL] Where to write the output array length into. This is always gonna be <c>hexstr_length / 2</c>, but you can still choose to write it out just to be sure. If you want to omit this: no problem.. just pass <c>NULL</c>!
 * @return <c>0</c> if conversion succeeded. <c>1</c> if one or more required arguments were <c>NULL</c> or invalid. <c>2</c> if the hexadecimal string is in an invalid format (e.g. not divisible by 2). <c>3</c> if output buffer size was insufficient (needs to be at least <c>(hexstr_length / 2) + 1</c> bytes).
 */
CECIES_API int cecies_hexstr2bin(const char* hexstr, size_t hexstr_length, unsigned char* output, size_t output_size, size_t* output_length);

/**
 * Converts a byte array to a hex string. <p>
 * A NUL-terminator is appended at the end of the output buffer, so make sure to allocate at least <c>(bin_length * 2) + 1</c> bytes!
 * @param bin The binary data to convert into hex string.
 * @param bin_length Length of the \p bin array.
 * @param output Where to write the hex string into.
 * @param output_size Maximum capacity of the \p output buffer. Make sure to allocate at least <c>(bin_length * 2) + 1</c> bytes!
 * @param output_length [OPTIONAL] Where to write the output string length into. This is always gonna be <c>bin_length * 2</c>, but you can still choose to write it out just to be sure. If you want to omit this: no problem.. just pass <c>NULL</c>!
 * @param uppercase Should the \p output string characters be UPPER- or lowercase?
 * @return <c>0</c> if conversion succeeded. <c>1</c> if one or more required arguments were <c>NULL</c> or invalid. <c>2</c> if the output buffer size is insufficient: please allocate at least <c>(bin_length * 2) + 1</c> bytes!
 */
CECIES_API int cecies_bin2hexstr(const unsigned char* bin, size_t bin_length, char* output, size_t output_size, size_t* output_length, bool uppercase);

/**
 * Gets the current CECIES version number as a human-readable string (e.g. <c>"2.1.2"</c>).
 * @return The stringified current CECIES version number.
 */
CECIES_API char* cecies_get_version_str();

/**
 * Gets the current CECIES version number as an unsigned integer (e.g. version <c>"2.1.2"</c> would return <c>212</c>).
 * @return The current CECIES version number.
 */
CECIES_API uint64_t cecies_get_version_nr();

/**
 * Checks whether CECIES fprintf is enabled (whether errors are fprintfed into stderr).
 * @return Whether errors are fprintfed into stderr or not.
 */
CECIES_API unsigned char cecies_is_fprintf_enabled();

/**
 * Like fprintf() except it doesn't do anything. Like printing into <c>/dev/null</c> :D lots of fun!
 * @param stream [IGNORED]
 * @param format [IGNORED]
 * @param ... [IGNORED]
 * @return <c>0</c>
 */
static inline int cecies_printvoid(FILE* stream, const char* format, ...)
{
    return 0;
}

/** @private */
CECIES_API extern int (*cecies_fprintf_fptr)(FILE* stream, const char* format, ...);

/**
 * Enables CECIES' use of fprintf().
 */
CECIES_API void cecies_enable_fprintf();

/**
 * Disables CECIES' use of fprintf().
 */
CECIES_API void cecies_disable_fprintf();

/** @private */
#define cecies_fprintf cecies_fprintf_fptr

/**
 * Gets a random big integer. This only features very limited randomness due to usage of <c>rand()</c>! <p>
 * **DO NOT USE THIS FOR ANY TYPE OF KEY GENERATION!** <p>
 * Current usage is for adding some lightweight additional entropy to the MbedTLS mbedtls_ctr_drbg_seed() function,
 * which only gives the advantage of having a slightly different per-app starting point for the seed (as stated in the MbedTLS documentation).
 * @return Random big number
 */
static inline unsigned long long int cecies_get_random_big_integer()
{
    srand((unsigned int)time(NULL) * (unsigned int)time(NULL));
    return rand() * rand() * rand() * rand();
}

/**
 * (Tries to) read from <c>/dev/urandom</c> (or Windows equivalent, yeah...) filling the given \p output_buffer with \p output_buffer_size random bytes.
 * @param output_buffer Where to write the random bytes into.
 * @param output_buffer_size How many random bytes to write into \p output_buffer
 */
CECIES_API void cecies_dev_urandom(unsigned char* output_buffer, size_t output_buffer_size);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_UTIL_H
