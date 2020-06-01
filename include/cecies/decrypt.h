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

/**
 * Asymmetrically decrypts the given data using ECIES over Curve448.
 * @param encrypted_data The data to decrypt.
 * @param encrypted_data_length The length of the data array.
 * @param private_key The private key to decrypt the data with (PEM-formatted).
 * @param private_key_length Length of the private_key string.
 * @param private_key_passphrase [OPTIONAL] The private key's passphrase (can be <c>NULL</c> if the key is not protected).
 * @param private_key_passphrase_length Length of the private_key_passphrase string (ignored if private_key_passphrase is <c>NULL</c>).
 * @param output Where to write the decrypted output into (please pre-allocate this big enough).
 * @param output_bufsize How big the output buffer is.
 * @param output_length Where to write the output buffer length into.
 * @return <c>0</c> if decryption succeeded; <c>1</c> if the data, private_key, output or output_length pointer was <c>NULL</c>; <c>2</c> if the output array is not big enough to contain the encrypted result; <c>3</c> if key parsing failed; <c>10</c> for anything else that went wrong for an undefined reason.
 */
int cecies_decrypt(const unsigned char* encrypted_data, size_t encrypted_data_length, const unsigned char* private_key, size_t private_key_length, const unsigned char* private_key_passphrase, size_t private_key_passphrase_length, unsigned char* output, size_t output_bufsize, size_t* output_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_DECRYPT_H
