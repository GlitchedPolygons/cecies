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

#ifndef CECIES_DECRYPT_H
#define CECIES_DECRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define CECIES_DECRYPT_ERROR_CODE_NULL_ARG 2000
#define CECIES_DECRYPT_ERROR_CODE_INVALID_ARG 2001
#define CECIES_DECRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE 2002

/**
 * Decrypts the given data using ECIES, Curve448 and AES256-CBC.
 * @param encrypted_data The data to decrypt.
 * @param encrypted_data_length The length of the data array.
 * @param private_key The private key to decrypt the data with.
 * @param private_key_length Length of the private_key string.
 * @param private_key_base64 Is the private key base64-encoded or raw? If this is false, the key will be directly fed into mbedtls_mpi_read_binary()!
 * @param output Where to write the decrypted output into (please pre-allocate this big enough).
 * @param output_bufsize How big the output buffer is. Please allocate at least \p encrypted_data_length bytes!
 * @param output_length Where to write the output buffer length into (how many bytes were written into it).
 * @return <c>0</c> if decryption succeeded;  error codes as defined inside the header file or MbedTLS otherwise.
 */
int cecies_decrypt(const unsigned char* encrypted_data, size_t encrypted_data_length, const unsigned char* private_key, size_t private_key_length, bool private_key_base64, unsigned char* output, size_t output_bufsize, size_t* output_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_DECRYPT_H
