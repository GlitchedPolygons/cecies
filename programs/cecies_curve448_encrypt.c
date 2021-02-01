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
#include <cecies/encrypt.h>
#include <mbedtls/platform_util.h>

int main(const int argc, const char* argv[])
{
    cecies_enable_fprintf();

    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        fprintf(stdout, "cecies_curve448_encrypt:  Encrypt a string using a Curve448 public key. Call this program using exactly 2 arguments;  the first one being the public key (hex-string) and the second the string to encrypt.\n");
        return 0;
    }

    if (argc != 3)
    {
        fprintf(stderr, "cecies_curve448_encrypt: wrong argument count. Check out \"cecies_curve448_encrypt --help\" for more details about how to use this!\n");
        return -1;
    }

    const char* public_key_hexstr = argv[1];
    const char* message = argv[2];

    const size_t public_key_hexstr_len = strlen(public_key_hexstr);
    const size_t message_len = strlen(message);

    if (public_key_hexstr_len != 112)
    {
        fprintf(stderr, "cecies_curve448_encrypt: Invalid public key format/length!\n");
        return -2;
    }

    cecies_curve448_key public_key;
    mbedtls_platform_zeroize(&public_key, sizeof(cecies_curve448_key));
    memcpy(public_key.hexstring, public_key_hexstr, public_key_hexstr_len);

    size_t olen = cecies_calc_base64_length(cecies_curve448_calc_output_buffer_needed_size(message_len));
    uint8_t* o = calloc(olen, sizeof(uint8_t));

    if (o == NULL)
    {
        fprintf(stderr, "cecies_curve448_encrypt: OUT OF MEMORY!\n");
        return -3;
    }

    int r = cecies_curve448_encrypt((uint8_t*)message, message_len, 0, public_key, o, olen, NULL, 1);
    if (r != 0)
    {
        free(o);
        return -4;
    }

    fprintf(stdout, "%s\n", o);

    free(o);
    return 0;
}
