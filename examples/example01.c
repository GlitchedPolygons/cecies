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
#include <stdint.h>
#include <string.h>
#include <cecies/util.h>
#include <cecies/encrypt.h>
#include <cecies/decrypt.h>

/*
 *     This is the example test string to encrypt and decrypt.
 */
static const char TEST_STRING[] = "Doctor Freeman. I realize this moment may not be the most convenient for a heart-to-heart, but I had to wait until your friends were otherwise occupied. Hm. There was a time they cared nothing for Miss Vance... When their only experience of humanity was a crowbar coming at them down a steel corridor.";

static const cecies_curve448_key TEST_PUBLIC_KEY = { .hexstring = "55a9b9d87a26c1add2f61a89f52de9a77fe80178a639a484a07bc7f17c3c1f5930082869f4d7eae98be394db2851fa44b6f8ce95127d9e86" };
static const cecies_curve448_key TEST_PRIVATE_KEY = { .hexstring = "92898bcfddf14e33d48ab16f46d8ad0290af234edfe3754a0f80528ecaafa6bb769a0f4c2601d48ee24ae38d0316103d8cf932a87df58844" };

int main(void)
{
    int s = 1;

    // sizeof(TEST_STRING) instead of strlen(TEST_STRING) because we also want to encrypt the NUL-terminator character along. Never forget the NUL-terminator in C-strings!
    const size_t TEST_STRING_LENGTH = sizeof(TEST_STRING);

    printf("\n---- CECIES ----\n-- Example 01 --\n\n");
    printf("Encrypting the following string:\n\n%s\n\n", TEST_STRING);

    uint8_t* encrypted_string;
    size_t encrypted_string_length;

    s = cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH, 0, TEST_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1);

    if (s != 0)
    {
        printf("Encryption failed! \"cecies_curve448_encrypt\" returned: %d\n", s);
        return s;
    }

    printf("Encrypted string >>> base64:\n\n%s\n\nStatus code: %d\n\n", encrypted_string, s);

    size_t decrypted_string_length;
    char* decrypted_string;

    s = cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 1, TEST_PRIVATE_KEY, (uint8_t**)&decrypted_string, &decrypted_string_length);

    printf("Decrypted string:\n\n%s\n\nStatus code: %d\n\n", decrypted_string, s);

    cecies_free(encrypted_string);
    cecies_free(decrypted_string);

    return s;
}