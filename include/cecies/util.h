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
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * Gets a random big integer. This only features very limited randomness due to usage of <c>rand()</c>! <p>
 * **DO NOT USE THIS FOR ANY TYPE OF KEY GENERATION!** <p>
 * Current usage is for adding some lightweight additional entropy to the MbedTLS mbedtls_ctr_drbg_seed() function,
 * which only gives the advantage of having a slightly different per-app starting point for the seed (as stated in the MbedTLS documentation).
 * @return Random big number
 */
static inline unsigned long long int cecies_get_random_big_integer()
{
    srand(time(NULL) * time(NULL));
    return rand() * rand() * rand() * rand();
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

    // 1:  IV (AES initialization vector)
    // 2:  Salt (for PBKDF2)
    // 3:  R (ephemeral public key)
    // 4:  Tag (from AES-GCM)
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
static int cecies_hexstr2bin(const unsigned char* hexstr, const size_t hexstr_length, unsigned char* output, const size_t output_size, size_t* output_length)
{
    if (hexstr == NULL || output == NULL || hexstr_length == 0)
    {
        return 1;
    }

    const size_t hl = hexstr[hexstr_length - 1] ? hexstr_length : hexstr_length - 1;

    if (hl % 2 != 0)
    {
        return 2;
    }

    const size_t final_length = hl / 2;

    if (output_size < final_length + 1)
    {
        return 3;
    }

    for (size_t i = 0, ii = 0; ii < final_length; i += 2, ii++)
    {
        output[ii] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
    }

    output[final_length] = '\0';

    if (output_length != NULL)
    {
        *output_length = final_length;
    }

    return 0;
}

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
static int cecies_bin2hexstr(const unsigned char* bin, const size_t bin_length, unsigned char* output, const size_t output_size, size_t* output_length, const bool uppercase)
{
    if (bin == NULL || bin_length == 0 || output == NULL)
    {
        return 1;
    }

    const size_t final_length = bin_length * 2;

    if (output_size < final_length + 1)
    {
        return 2;
    }

    const char* format = uppercase ? "%02X" : "%02x";

    for (size_t i = 0; i < bin_length; i++)
    {
        sprintf((char*)output + i * 2, format, bin[i]);
    }

    output[final_length] = '\0';

    if (output_length != NULL)
    {
        *output_length = final_length;
    }

    return 0;
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
