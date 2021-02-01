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

#include <stdio.h>
#include <string.h>
#include <cecies/util.h>
#include <cecies/encrypt.h>
#include <cecies/decrypt.h>

/*
 *     This is the example test string to encrypt and decrypt.
 */
static const char TEST_STRING[] = "The borderworld, Xen, is in our control for the time being, thanks to you. Quite a nasty piece of work you managed over there. I am impressed.";

static const cecies_curve448_key TEST_PUBLIC_KEY = { .hexstring = "27db8963fa686b2383d6efb972e18959a72edfc4f6b590beddc7accecaf7195f673435066513c94a2583fec8a4d68484e872d3ae54e3a811" };
static const cecies_curve448_key TEST_PRIVATE_KEY = { .hexstring = "8dfd91d90cc54f518359b2a72dc1ad03e6b96e54603c02a94e2edd1d82c4c3a594bec4cbc36fcedce972e2d21eb680dd41301b83a3953f70" };

int main(void)
{
    int s = 1;

    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;

    size_t encrypted_string_length;
    size_t decrypted_string_length;

    const size_t TEST_STRING_LENGTH = sizeof(TEST_STRING);

    printf("\n---- CECIES ----\n-- Example 03 --\n\n");
    printf("Encrypting the following string:\n\n%s\n\n", TEST_STRING);

    // Base64-encoding your encrypted output by passing 1 into that last function parameter requires more memory, but allows an easy textual transmission/representation of the ciphertext.

    s = cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH, 0, TEST_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0);

    printf("Status code: %d\n\n", s);

    if (s != 0)
    {
        goto exit;
    }

    printf("Encrypted string >>> binary:\n\n%s\n\n", encrypted_string);

    printf("Encrypted string >>> hexstr:\n\n");

    for (int i = 0; i < encrypted_string_length; ++i)
    {
        printf("%02x", encrypted_string[i]);
    }

    s = cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, TEST_PRIVATE_KEY, &decrypted_string, &decrypted_string_length);

    printf("\n\nStatus code: %d\n\n", s);

    if (s != 0)
    {
        goto exit;
    }

    printf("Decrypted string:\n\n%s\n\n", decrypted_string);

exit:
    free(encrypted_string);
    free(decrypted_string);
    return s;
}