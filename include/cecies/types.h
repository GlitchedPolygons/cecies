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

#if defined(_WIN32) && defined(CECIES_DLL)
#ifdef CECIES_BUILD_DLL
#define CECIES_API __declspec(dllexport)
#else
#define CECIES_API __declspec(dllimport)
#endif
#else
#define CECIES_API
#endif

/**
 * Contains a Curve25519 key, encoded as a NUL-terminated hex-string.
 */
typedef struct cecies_curve25519_key
{
    /**
     * Hex-encoded string of a 32-byte Curve25519 key. <p>
     * For public keys, the 0x04 byte prefix is omitted. <p>
     * The 65th character is the NUL-terminator.
     */
    char hexstring[64 + 1];
} cecies_curve25519_key;

/**
 * Contains a stack-allocated cecies_curve25519_key keypair.
 */
typedef struct cecies_curve25519_keypair
{
    /**
     * The public key (formatted as a hex string). <p>
     * 64 bytes of hex string + 1 NUL-terminator.
     */
    cecies_curve25519_key public_key;

    /**
     * The private key (formatted as a hex string). <p>
     * 64 bytes of hex string + 1 NUL-terminator.
     */
    cecies_curve25519_key private_key;
} cecies_curve25519_keypair;

/**
 * Contains a Curve448 key, encoded as a NUL-terminated hex-string.
 */
typedef struct cecies_curve448_key
{
    /**
     * Hex-encoded string of a 56-byte Curve448 key. <p>
     * For public keys, the 0x04 byte prefix is omitted. <p>
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
     * EC key encoding standard is omitted in this implementation!
     */
    cecies_curve448_key public_key;

    /**
     * The private key (formatted as a hex string). <p>
     * 112 bytes of hex string + 1 NUL-terminator.
     */
    cecies_curve448_key private_key;
} cecies_curve448_keypair;

/**
 * @brief Struct containing the output from a call to the cecies_new_guid() function. <p>
 * 36 characters (only 32 if you chose to omit the hyphens) + 1 NUL terminator.
 */
typedef struct cecies_guid
{
    /** NUL-terminated string containing the GUID. */
    char string[36 + 1];
} cecies_guid;

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_TYPES_H
