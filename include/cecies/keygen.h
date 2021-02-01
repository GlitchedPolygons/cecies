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
 *  @file keygen.h
 *  @author Raphael Beck
 *  @brief Curve25519 and Curve448 key-pair generators (both export their output into NUL-terminated, hex-encoded strings).
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

#include "util.h"
#include "types.h"

/**
 * Generates a CECIES Curve25519 keypair and writes it into the specified output buffers.
 * @param output The cecies_curve25519_keypair instance into which to write the generated key-pair.
 * @param additional_entropy [OPTIONAL] Additional entropy bytes for the CSPRNG. Can be set to <c>NULL</c> if you wish not to add custom entropy.
 * @param additional_entropy_length [OPTIONAL] Length of the \p additional_entropy array. If \p additional_entropy is <c>NULL</c>, this value is ignored.
 * @return <c>0</c> if key generation succeeded; error codes as defined inside the header file or MbedTLS otherwise.
 */
CECIES_API int cecies_generate_curve25519_keypair(cecies_curve25519_keypair* output, const uint8_t* additional_entropy, size_t additional_entropy_length);

/**
 * Generates a CECIES Curve448 keypair and writes it into the specified output buffers.
 * @param output The cecies_curve448_keypair instance into which to write the generated key-pair.
 * @param additional_entropy [OPTIONAL] Additional entropy bytes for the CSPRNG. Can be set to <c>NULL</c> if you wish not to add custom entropy.
 * @param additional_entropy_length [OPTIONAL] Length of the \p additional_entropy array. If \p additional_entropy is <c>NULL</c>, this value is ignored.
 * @return <c>0</c> if key generation succeeded; error codes as defined inside the header file or MbedTLS otherwise.
 */
CECIES_API int cecies_generate_curve448_keypair(cecies_curve448_keypair* output, const uint8_t* additional_entropy, size_t additional_entropy_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_KEYGEN_H
