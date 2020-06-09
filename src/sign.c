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

#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md_internal.h>

#include "cecies/util.h"
#include "cecies/sign.h"

int cecies_sign(const unsigned char* data, const size_t data_length, const unsigned char* private_key, const size_t private_key_length, const bool private_key_base64, unsigned char* output, const size_t output_bufsize, size_t* output_length)
{
    if (data == NULL //
            || private_key == NULL //
            || output == NULL //
            || output_length == NULL)
    {
        fprintf(stderr, "ECDSA signing failed: one or more NULL arguments.");
        return CECIES_SIGN_ERROR_CODE_NULL_ARG;
    }

    if (data_length == 0 //
            || private_key_length == 0 //
            || output_bufsize == 0)
    {
        fprintf(stderr, "ECDSA signing failed: one or more invalid arguments.");
        return CECIES_SIGN_ERROR_CODE_INVALID_ARG;
    }

    int ret = 1;

    unsigned char sha512[64];
    memset(sha512, 0x00, 64);

    mbedtls_ecp_group ecp_group;
    mbedtls_ecdsa_context ecdsa;
    mbedtls_md_context_t md_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_mpi dA;

    mbedtls_ecp_group_init(&ecp_group);
    mbedtls_ecdsa_init(&ecdsa);
    mbedtls_md_init(&md_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&dA);

    ret = mbedtls_ecp_group_load(&ecp_group, MBEDTLS_ECP_DP_CURVE448);
    if (ret != 0)
    {
        fprintf(stderr, "MbedTLS ECP group setup failed! mbedtls_ecp_group_load returned %d\n", ret);
        goto exit;
    }

    unsigned char pers[32];
    snprintf((char*)pers, sizeof(pers), "cecies_PERS_?~'\"@#937%llu", cecies_get_random_big_integer());

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, sizeof(pers));
    if (ret != 0)
    {
        fprintf(stderr, "MbedTLS PRNG seed failed! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_sha512_ret(data, data_length, sha512, 0);
    if (ret != 0)
    {
        fprintf(stderr, "ECDSA signing failed while hashing data using SHA-512! mbedtls_sha512_ret returned %d\n", ret);
        goto exit;
    }

    unsigned char sig[2048];
    size_t sig_len;

    if ((ret = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA512, sha512, 64, sig, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        mbedtls_printf("ECDSA signing failed! mbedtls_ecdsa_write_signature returned %d\n", ret);
        goto exit;
    }

exit:

    mbedtls_ecp_group_free(&ecp_group);
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_md_free(&md_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_mpi_free(&dA);

    return ret;
}