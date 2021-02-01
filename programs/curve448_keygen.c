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
#include <cecies/keygen.h>
#include <mbedtls/sha512.h>
#include <mbedtls/platform_util.h>

int main(int argc, const char* argv[])
{
    cecies_enable_fprintf();

    cecies_curve448_keypair keypair;

    uint8_t additional_entropy[128];

    for (int i = 0; i < argc; ++i)
    {
        const char* arg = argv[i];
        mbedtls_sha512_ret((const unsigned char*)arg, strlen(arg), additional_entropy + (64 * (i % 2)), 0);
    }

    mbedtls_sha512_ret(additional_entropy, sizeof(additional_entropy), additional_entropy + 64, 0);

    const int r = cecies_generate_curve448_keypair(&keypair, additional_entropy, sizeof additional_entropy);
    if (r != 0)
    {
        return r;
    }

    fprintf(stdout, "{\"curve448_private_key\":\"%s\",\"curve448_public_key\":\"%s\"}\n", keypair.private_key.hexstring, keypair.public_key.hexstring);

    // Cleanup:
    mbedtls_platform_zeroize(&keypair, sizeof(cecies_curve448_keypair));
    mbedtls_platform_zeroize(additional_entropy, sizeof(additional_entropy));
    return 0;
}
