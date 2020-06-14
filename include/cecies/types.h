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
 *  @file types.h
 *  @author Raphael Beck
 *  @brief CECIES types.
 */

#ifndef CECIES_TYPES_H
#define CECIES_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Contains a Curve448 key encoded as a NUL-terminated hex-string.
 */
typedef struct cecies_curve448_key
{
    /**
     * Hex-encoded string of a 56-byte Curve448 key.
     * For public keys, the 0x04 byte prefix is omitted.
     * The 113th character is the NUL-terminator.
     */
    char hexstring[112 + 1];
} cecies_curve448_key;

/**
 * Contains a stack-allocated Curve448 keypair.
 */
typedef struct cecies_curve448_keypair
{
    /**
     * The public key (formatted as a hex string). <p>
     * 112 bytes of hex string + 1 NUL-terminator. <p>
     * The <c>0x04</c> prefix byte that's required by the
     * EC key encoding standard is omitted:
     * add it back in again yourself when parsing!
     */
    cecies_curve448_key public_key;

    /**
     * The private key (formatted as a hex string). <p>
     * 112 bytes of hex string + 1 NUL-terminator.
     */
    cecies_curve448_key private_key;
} cecies_curve448_keypair;

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_TYPES_H
