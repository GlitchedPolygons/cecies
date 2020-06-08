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

#ifndef CECIES_UTIL_H
#define CECIES_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * Gets a random 12 digit integer (only limited randomness due to usage of <c>rand()</c>).
 * @return Random number [100000000000; 999999999999]
 */
static inline unsigned long long int cecies_get_random_12digit_integer()
{
    srand(time(NULL) * time(NULL));
    const unsigned long long int min = 100000000000;
    const unsigned long long int max = 999999999999;
    return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}

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
 * Gets the minimum amount of needed buffer size for a given encryption with a given plaintext data length.
 * @param plaintext_length The amount of bytes to encrypt.
 * @return The min. buffer size for encrypting \p plaintext_length bytes of data.
 */
static inline size_t cecies_calc_output_buffer_needed_size(const size_t plaintext_length)
{
    // Data length: 8
    // IV length: 16
    // Salt length: 32
    // R length: 113

    return 8 + 16 + 32 + 113 + cecies_calc_aes_cbc_ciphertext_length(plaintext_length);
}

/**
 * Calculates the output length in bytes after base64-encoding \p data_length bytes.
 * @param data_length The number of bytes you'd base64-encode.
 * @return <c>(4 * data_length / 3 + 3) & ~3</c>
 */
static inline size_t cecies_calc_base64_length(const size_t data_length)
{
    return (4 * data_length / 3 + 3) & ~(unsigned)3;
}

static const unsigned char empty32[32] = {
    //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
};

static const unsigned char empty64[64] = {
    //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
};

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_UTIL_H
