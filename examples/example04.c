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
static const char TEST_STRING[] = "Doctor Freeman. I realize this moment may not be the most convenient for a heart-to-heart, but I had to wait until your friends were otherwise occupied. Hm. There was a time they cared nothing for Miss Vance... When their only experience of humanity was a crowbar coming at them down a steel corridor.";

static const char TEST_PUBLIC_KEY[] = "04ebf5be2d15c7fb53ff38a5759f78f2d87d77f0d243374ad1cceae84a7dc1d50ef5acda5b7b7359d49b7457e8537277e78ace1db6ca363221";

static const char TEST_PRIVATE_KEY[] = "dbee49abcf57dc0e2eb3b35ff00860fa683e0ac725c9e5d576340724f4894fac85730c93f688cbad98f98516d27e255ffeffd2365563cf24";

int main(void)
{
    int s = 1;
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;
    const size_t TEST_STRING_LENGTH = sizeof(TEST_STRING);

    printf("\n---- CECIES ----\n-- Example 04 --\n\n");
    printf("Encrypting the following string:\n\n%s\n\n", TEST_STRING);

    // Here's how to encrypt data and base64 encrypt it
    // using the cecies_calc_output_buffer_needed_size()
    // function to allocate the exactly right amount of bytes.

    encrypted_string_length = cecies_calc_base64_length(cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH));
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    // You can pass NULL to the output_length pointer argument, since you already calculated the size above.
    s = cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH, TEST_PUBLIC_KEY, 0, encrypted_string, encrypted_string_length, NULL, true);

    printf("Status code: %d\n\n", s);

    if (s != 0)
    {
        goto exit;
    }

    printf("Encrypted string >>> base64:\n\n%s\n\n", encrypted_string);

    // When unsure, allocate the same amount as the input encrypted data buffer. That's guaranteed to work.
    decrypted_string = malloc(encrypted_string_length);
    memset(decrypted_string, 0x00, encrypted_string_length);

    s = cecies_decrypt(encrypted_string, encrypted_string_length, true, TEST_PRIVATE_KEY, 0, decrypted_string, encrypted_string_length, &decrypted_string_length);

    printf("Status code: %d\n\n", s);

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