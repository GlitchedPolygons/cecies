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
#include <string.h>
#include <cecies/util.h>
#include <mbedtls/sha256.h>
#include <sodium.h>

int main(int argc, const char* argv[])
{
    unsigned char additional_entropy[512];
    cecies_dev_urandom(additional_entropy, 256);

    size_t rem = 256;
    for (int i = 1; i < argc && rem > 0; i++)
    {
        const char* istr = argv[i];
        const size_t ilen = CECIES_MIN(rem, strlen(istr));
        snprintf((char*)(additional_entropy + (512 - rem)), ilen, "%s", istr);
        rem -= ilen;
    }

    unsigned char seed[32];
    unsigned char public_key[32];
    unsigned char private_key[64];

    memset(seed, 0x00, sizeof(seed));
    memset(public_key, 0x00, sizeof(public_key));
    memset(private_key, 0x00, sizeof(private_key));

    if (mbedtls_sha256_ret(additional_entropy, sizeof(additional_entropy), seed, 0) != 0)
    {
        fprintf(stderr, "ed25519_keygen.c: Key generation failed while hashing additional entropy using SHA2-512...");
        return 1;
    }

    crypto_sign_ed25519_seed_keypair(public_key, private_key, seed);

    fprintf(stdout, "{\"ed25519_private_key\":\"");
    for (int i = 0; i < sizeof(private_key); ++i)
    {
        fprintf(stdout, "%02x", private_key[i]);
    }

    fprintf(stdout, "\",\"ed25519_public_key\":\"");
    for (int i = 0; i < sizeof(public_key); ++i)
    {
        fprintf(stdout, "%02x", public_key[i]);
    }

    fprintf(stdout, "\"}\n");

    // Cleanup:
    memset(seed, 0x00, sizeof(seed));
    memset(public_key, 0x00, sizeof(public_key));
    memset(private_key, 0x00, sizeof(private_key));

    return 0;
}
