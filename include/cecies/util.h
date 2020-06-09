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
 * Gets a random big integer (only featuring limited randomness due to usage of <c>rand()</c>).
 * @return Random big number
 */
static inline unsigned long long int cecies_get_random_big_integer()
{
    srand(time(NULL) * time(NULL));
    return rand() * rand() * rand()* rand();
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
    //     1    2    3     4
    return 16 + 32 + 113 + 16 + plaintext_length;

    // 1:  IV
    // 2:  Salt
    // 3:  R
    // 4:  Tag
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
