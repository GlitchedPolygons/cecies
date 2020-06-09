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

static const char TEST_PUBLIC_KEY[] = "BMAocEd2hsZvNRynFSu8YeCfOu2wkXMALnDkr2hALy5cfiECpi2b21j9lXpoijwBkULMy234iR69AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

static const char TEST_PRIVATE_KEY[] = "8FNsJbVMlSwr41fb8ktgWjG8WyyAup1j0icaspuiTtCxt7C//m84283s/VK8NDvstvxho2PR5qA=";

int main(void)
{
    int s = 1;

    // sizeof(TEST_STRING) instead of strlen(TEST_STRING) because we also want to encrypt the NUL-terminator character along. Never forget the NUL-terminator in C-strings!
    const size_t TEST_STRING_LENGTH = sizeof(TEST_STRING);

    printf("\n---- CECIES ----\n-- Example 01 --\n\n");
    printf("Encrypting the following string:\n%s\n\n", TEST_STRING);

    size_t encrypted_string_length;
    unsigned char encrypted_string[1024];
    memset(encrypted_string, 0x00, sizeof(encrypted_string));

    s = cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH, (unsigned char*)TEST_PUBLIC_KEY, strlen(TEST_PUBLIC_KEY), true, encrypted_string, sizeof(encrypted_string), &encrypted_string_length, true);

    printf("Encrypted string:\n%s\n\n", encrypted_string);

    size_t decrypted_string_length;
    char decrypted_string[1024];
    memset(decrypted_string, 0x00, sizeof(decrypted_string));

    s = cecies_decrypt(encrypted_string, encrypted_string_length, true, (unsigned char*)TEST_PRIVATE_KEY, strlen(TEST_PRIVATE_KEY), true, (unsigned char*)decrypted_string, sizeof(decrypted_string), &decrypted_string_length);

    printf("Decrypted string:\n%s\n\n", decrypted_string);

    return s;
}