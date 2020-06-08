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

#ifndef CECIES_KEYGEN_H
#define CECIES_KEYGEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define CECIES_KEYGEN_ERROR_CODE_NULL_ARG 7000
#define CECIES_KEYGEN_ERROR_CODE_INVALID_ARG 7001
#define CECIES_KEYGEN_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE 7002

/**
 * Generates a CECIES keypair (currently using Curve448) and writes it into the specified output buffers.
 * @param base64 Should the generated keys be exported into the output buffers as human-readable base64-encoded strings or just raw binary data?
 * @param output_private_key_buffer Private key output buffer into which to write the private key.
 * @param output_private_key_buffer_size Private key output buffer size. Make sure to allocate enough space!
 * @param output_private_key_buffer_length How many bytes were written into the \p output_private_key_buffer output buffer.
 * @param output_public_key_buffer Public key output buffer into which to write the public key.
 * @param output_public_key_buffer_size Public key output buffer size. Make sure to allocate enough space!
 * @param output_public_key_buffer_length How many bytes were written into the \p output_public_key_buffer output buffer.
 * @return <c>0</c> if key generation succeeded; error codes as defined inside the header file otherwise.
 */
int cecies_generate_curve448_keypair(bool base64, unsigned char* output_private_key_buffer, size_t output_private_key_buffer_size, size_t* output_private_key_buffer_length, unsigned char* output_public_key_buffer, size_t output_public_key_buffer_size, size_t output_public_key_buffer_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_KEYGEN_H
