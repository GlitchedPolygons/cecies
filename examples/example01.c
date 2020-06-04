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

/*
 *     The following test keys were generated using OpenSSL 1.1.1:
 *
 *          openssl genpkey -algorithm X448 -out private.key.pem
 *          openssl pkey -in private.key.pem -pubout -out public.key.pem
 *
 */

static const char TEST_PUBKEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                  "MEIwBQYDK2VvAzkAPzwjOQbnir+CBZaHGFmu87nhvFG157EqSbIr9abKzJ03rYvO\n"
                                  "hSMqsFjfzdoi+ux231bLRghXC2Y=\n"
                                  "-----END PUBLIC KEY-----";

static const char TEST_PRVKEY[] = "-----BEGIN PRIVATE KEY-----\n"
                                  "MEYCAQAwBQYDK2VvBDoEOHTlbVSR8S8cY+/2e02dUZ0zwUVsgsEMcj2JcUpYkfGS\n"
                                  "1og1X8lRZ5K4BytAdhW/MEHP+xKDI7vp\n"
                                  "-----END PRIVATE KEY-----";

int main(void)
{
    printf("\n---- CECIES ----\n-- Example 01 --\n\n");
    printf("Encrypting the following string: \n\n %s \n\n", TEST_STRING);

    size_t output_length;
    unsigned char output[256];
    memset(output, 0x00, sizeof(output));

    cecies_encrypt((unsigned char*)TEST_STRING, strlen(TEST_STRING), (unsigned char*)TEST_PUBKEY, strlen(TEST_PUBKEY), output, sizeof(output), &output_length);

    printf("Encrypted string: %s", output);

    size_t decrypted_string_length;
    char decrypted_string[256];
    memset(decrypted_string, 0x00, sizeof(decrypted_string));

    cecies_decrypt(output, output_length, (unsigned char*)TEST_PRVKEY, strlen(TEST_PRVKEY), NULL, 0, (unsigned char*)decrypted_string, sizeof(decrypted_string), &decrypted_string_length);

    printf("Decrypted string: %s", decrypted_string);
}