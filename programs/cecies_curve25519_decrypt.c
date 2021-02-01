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
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cecies/util.h>
#include <cecies/decrypt.h>
#include <mbedtls/platform_util.h>

int main(const int argc, const char* argv[])
{
    cecies_enable_fprintf();

    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        fprintf(stdout, "cecies_curve25519_decrypt:  Decrypt a string using a Curve25519 private key. Call this program using exactly 2 arguments;  the first one being the private key (hex-string) and the second the string to decrypt.\n");
        return 0;
    }

    if (argc != 3)
    {
        fprintf(stderr, "cecies_curve25519_decrypt: wrong argument count. Check out \"cecies_curve25519_decrypt --help\" for more details about how to use this!\n");
        return -1;
    }

    const char* private_key_hexstr = argv[1];
    const char* message = argv[2];

    const size_t private_key_hexstr_len = strlen(private_key_hexstr);
    const size_t message_len = strlen(message);

    if (private_key_hexstr_len != 64)
    {
        fprintf(stderr, "cecies_curve25519_decrypt: Invalid private key format/length!\n");
        return -2;
    }

    cecies_curve25519_key private_key = { 0x00 };
    memcpy(private_key.hexstring, private_key_hexstr, private_key_hexstr_len);

    size_t olen = 0;
    uint8_t* o = calloc(message_len, sizeof(uint8_t));

    if (o == NULL)
    {
        fprintf(stderr, "cecies_curve25519_decrypt: OUT OF MEMORY!\n");
        mbedtls_platform_zeroize(&private_key, sizeof(cecies_curve25519_key));
        return -3;
    }

    int r = cecies_curve25519_decrypt((uint8_t*)message, message_len, 1, private_key, o, message_len, &olen);
    if (r != 0)
    {
        mbedtls_platform_zeroize(o, message_len);
        mbedtls_platform_zeroize(&private_key, sizeof(cecies_curve25519_key));
        free(o);
        return -4;
    }

    fprintf(stdout, "%s\n", o);

    mbedtls_platform_zeroize(o, message_len);
    mbedtls_platform_zeroize(&private_key, sizeof(cecies_curve25519_key));
    free(o);
    return 0;
}
