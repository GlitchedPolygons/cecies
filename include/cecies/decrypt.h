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
 *  @file decrypt.h
 *  @author Raphael Beck
 *  @brief ECIES decryption implementation using Curve25519 or Curve448, AES256-GCM and MbedTLS.
 */

#ifndef CECIES_DECRYPT_H
#define CECIES_DECRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "cecies/types.h"

/**
 * Decrypts the given data using ECIES, Curve25519 and AES256-GCM.
 * @param encrypted_data The data to decrypt.
 * @param encrypted_data_length The length of the data array.
 * @param encrypted_data_base64 Is the input \p encrypted_data base64-encoded?
 * @param private_key The private key to decrypt the data with (hex-string, as is the output of cecies_generate_curve25519_keypair()).
 * @param output Where to write the decrypted output into (please pre-allocate this big enough; if unsure, allocate \p encrypted_data_length bytes!).
 * @param output_bufsize How big the output buffer is. Please allocate at least \p encrypted_data_length bytes!
 * @param output_length Where to write the output buffer length into (how many bytes were written into it).
 * @return <c>0</c> if decryption succeeded; error codes as defined inside the header file or MbedTLS otherwise.
 */
int cecies_curve25519_decrypt(unsigned char* encrypted_data, const size_t encrypted_data_length, const bool encrypted_data_base64, cecies_curve25519_key private_key, unsigned char* output, const size_t output_bufsize, size_t* output_length);

/**
 * Decrypts the given data using ECIES, Curve448 and AES256-GCM.
 * @param encrypted_data The data to decrypt.
 * @param encrypted_data_length The length of the data array.
 * @param encrypted_data_base64 Is the input \p encrypted_data base64-encoded?
 * @param private_key The private key to decrypt the data with (hex-string, as is the output of cecies_generate_curve448_keypair()).
 * @param output Where to write the decrypted output into (please pre-allocate this big enough; if unsure, allocate \p encrypted_data_length bytes!).
 * @param output_bufsize How big the output buffer is. Please allocate at least \p encrypted_data_length bytes!
 * @param output_length Where to write the output buffer length into (how many bytes were written into it).
 * @return <c>0</c> if decryption succeeded; error codes as defined inside the header file or MbedTLS otherwise.
 */
int cecies_curve448_decrypt(unsigned char* encrypted_data, const size_t encrypted_data_length, const bool encrypted_data_base64, cecies_curve448_key private_key, unsigned char* output, const size_t output_bufsize, size_t* output_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_DECRYPT_H
