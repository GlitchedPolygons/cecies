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

#ifndef CECIES_SIGN_H
#define CECIES_SIGN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define CECIES_SIGN_ERROR_CODE_NULL_ARG 3000
#define CECIES_SIGN_ERROR_CODE_INVALID_ARG 3001
#define CECIES_SIGN_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE 3002
#define CECIES_SIGN_ERROR_CODE_OUT_OF_MEMORY 3003

/**
 * Signs a set of given data by calculating the data's SHA-512 hash and then creating an ECDSA signature from that using the provided private Curve448 key.
 * @param data The data to sign.
 * @param data_length The length of the \p data array.
 * @param private_key The private key to use for signing.
 * @param private_key_length Length of the \p private_key array.
 * @param private_key_base64 Is the private key base64-encoded or raw? If this is false, the key will be directly fed into mbedtls_mpi_read_binary()!
 * @param output The output buffer into which to write the ECDSA signature.
 * @param output_bufsize The output buffer size (please allocate enough space!).
 * @param output_length Where to write the output buffer length into (how many bytes were written into it).
 * @return <c>0</c> if signing succeeded; error codes as defined inside the header file or MbedTLS otherwise.
 */
int cecies_sign(const unsigned char* data, size_t data_length, const unsigned char* private_key, size_t private_key_length, bool private_key_base64, unsigned char* output, size_t output_bufsize, size_t* output_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_SIGN_H
