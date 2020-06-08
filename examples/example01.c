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

static const char TEST_PUBKEY[] = "BKq8EdAQ9UFQylD+VeJ8EfjbsMYm0eVprZANBTnqDRx4j/HWjYFyuo8IZ+vfz0rH/GT4SBQrqhWSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

static const char TEST_PRVKEY[] = "-----BEGIN PRIVATE KEY-----\n"
                                  "MEYCAQAwBQYDK2VvBDoEOIwgnBK8yqb5Ka+wG69cZEBpu4Tsqd73gyEz6PLRrbN5\n"
                                  "IyGqcboW8RXj7vjcpgpEvLgf7FK5Cbes\n"
                                  "-----END PRIVATE KEY-----";

int main(void)
{
    printf("\n---- CECIES ----\n-- Example 01 --\n\n");
    printf("Encrypting the following string: \n\n %s \n\n", TEST_STRING);

    size_t output_length;
    unsigned char output[1024];
    memset(output, 0x00, sizeof(output));

    cecies_encrypt((unsigned char*)TEST_STRING, strlen(TEST_STRING), (unsigned char*)TEST_PUBKEY, strlen(TEST_PUBKEY), true, output, sizeof(output), &output_length);

    printf("Encrypted string: %s \n\n", output);

    size_t decrypted_string_length;
    char decrypted_string[256];
    memset(decrypted_string, 0x00, sizeof(decrypted_string));

    cecies_decrypt(output, output_length, (unsigned char*)TEST_PRVKEY, strlen(TEST_PRVKEY), NULL, 0, (unsigned char*)decrypted_string, sizeof(decrypted_string), &decrypted_string_length);

    printf("Decrypted string: %s \n\n", decrypted_string);
}