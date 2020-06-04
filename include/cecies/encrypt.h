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

#ifndef CECIES_ENCRYPT_H
#define CECIES_ENCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/***
 * Asymmetrically encrypts the given data using ECIES over Curve448.
 * @param data The data to encrypt.
 * @param data_length The length of the data array.
 * @param public_key The public key to encrypt the data with (PEM-formatted).
 * @param public_key_length Length of the public_key string.
 * @param output Where to write the encrypted output into (please pre-allocate this big enough).
 * @param output_bufsize How big the output buffer is.
 * @param output_length Where to write the output buffer length into (this is less than the provided output_bufsize).
 * @return <c>0</c> if encryption succeeded; <c>1</c> if the data, public_key, output or output_length pointer was <c>NULL</c>; <c>2</c> if the output array is not big enough to contain the encrypted result; <c>3</c> if key parsing failed; <c>10</c> for anything else that went wrong for an undefined reason.
 */
int cecies_encrypt(const unsigned char* data, size_t data_length, const unsigned char* public_key, size_t public_key_length, unsigned char* output, size_t output_bufsize, size_t* output_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_ENCRYPT_H
