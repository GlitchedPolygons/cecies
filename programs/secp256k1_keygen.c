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
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

int main(int argc, const char* argv[])
{
    cecies_enable_fprintf();

    mbedtls_ecdsa_context ecdsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecdsa_init(&ecdsa);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    size_t public_key_length;
    unsigned char public_key[128];
    memset(public_key, 0x00, sizeof(public_key));

    size_t private_key_length;
    unsigned char private_key[128];
    memset(private_key, 0x00, sizeof(private_key));

    unsigned char additional_entropy[128];
    size_t rem = sizeof(additional_entropy);

    for (int i = 1; i < argc && rem > 0; i++)
    {
        const char* istr = argv[i];
        const size_t ilen = CECIES_MIN(rem, strlen(istr));
        snprintf((char*)(additional_entropy + (128 - rem)), ilen, "%s", istr);
        rem -= ilen;
    }

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, additional_entropy, sizeof(additional_entropy));
    if (ret != 0)
    {
        fprintf(stderr, "secp256k1 key generation failed: \"mbedtls_ctr_drbg_seed\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256K1, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        fprintf(stderr, "secp256k1 key generation failed: \"mbedtls_ecdsa_genkey\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_point_write_binary(&ecdsa.grp, &ecdsa.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &public_key_length, public_key, sizeof(public_key));
    if (ret != 0)
    {
        fprintf(stderr, "secp256k1 key generation failed: \"mbedtls_ecp_point_write_binary\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_mpi_write_binary(&ecdsa.d, private_key, sizeof(private_key));
    if (ret != 0)
    {
        fprintf(stderr, "secp256k1 key generation failed: \"mbedtls_mpi_write_binary\" returned: %d\n", ret);
        goto exit;
    }

    private_key_length = mbedtls_mpi_size(&ecdsa.d);

    fprintf(stdout, "{\"secp256k1_private_key\":\"");
    for (int i = 0; i < private_key_length; ++i)
    {
        fprintf(stdout, "%02x", (private_key + 128 - private_key_length)[i]);
    }

    fprintf(stdout, "\",\"secp256k1_public_key\":\"");
    for (int i = 0; i < public_key_length; ++i)
    {
        fprintf(stdout, "%02x", public_key[i]);
    }

    fprintf(stdout, "\"}\n");

exit:
    // Cleanup:
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    memset(public_key, 0x00, sizeof(public_key));
    memset(private_key, 0x00, sizeof(private_key));
    memset(additional_entropy, 0x00, sizeof(additional_entropy));
    return 0;
}
