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
#include <cecies/encrypt.h>
#include <cecies/decrypt.h>

/*
 *     This is the example test string to encrypt and decrypt.
 */
static const char TEST_STRING[] = "Lorem ipsum dolor sick fuck amend something something ...";

static const char TEST_PUBLIC_KEY[] = "0450430325551ee86a6d9216947b5bdf04314771028e847029def87eb18474e10dcd981d72a2f51eff20ac1c1a3375850e0e53f1b065923304";

static const char TEST_PRIVATE_KEY[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

int main(void)
{
    int s = 1;

    // sizeof(TEST_STRING) instead of strlen(TEST_STRING) because we also want to encrypt the NUL-terminator character along. Never forget the NUL-terminator in C-strings!
    const size_t TEST_STRING_LENGTH = sizeof(TEST_STRING);

    printf("\n---- CECIES ----\n-- Example 01 --\n\n");
    printf("Encrypting the following string:\n\n%s\n\n", TEST_STRING);

    size_t encrypted_string_length;
    unsigned char encrypted_string[1024];
    memset(encrypted_string, 0x00, sizeof(encrypted_string));

    // In this example we allocate "enough" space on the stack because we know the message is short and predictable.
    // But if you don't know how big you should allocate your output buffer to contain the encrypted data,
    // you can make use of the cecies_calc_output_buffer_needed_size(size_t) function inside util.h!
    // Just keep in mind that if you choose to base64-encode too, allocate cecies_calc_base64_length(cecies_calc_output_buffer_needed_size(size_t))
    // bytes, because base64-encoding always needs more space. See example04 for more details about this scenario.

    s = cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH, TEST_PUBLIC_KEY, 0, encrypted_string, sizeof(encrypted_string), &encrypted_string_length, true);

    printf("Encrypted string >>> base64:\n\n%s\n\nStatus code: %d\n\n", encrypted_string, s);

    size_t decrypted_string_length;
    char decrypted_string[1024];
    memset(decrypted_string, 0x00, sizeof(decrypted_string));

    s = cecies_decrypt(encrypted_string, encrypted_string_length, true, TEST_PRIVATE_KEY, 0, (unsigned char*)decrypted_string, sizeof(decrypted_string), &decrypted_string_length);

    printf("Decrypted string:\n\n%s\n\nStatus code: %d\n\n", decrypted_string, s);

    return s;
}