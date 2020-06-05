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

#include <mbedtls/pk.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>
#include <mbedtls/ctr_drbg.h>
#include "cecies/encrypt.h"

static inline long long int get_random_pers_int()
{
    const long long int min = 100000000000;
    const long long int max = 999999999999;
    return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}

int cecies_encrypt(const unsigned char* data, const size_t data_length, const unsigned char* public_key, const size_t public_key_length, unsigned char* output, const size_t output_bufsize, size_t* output_length)
{
    int ret = 1;

    mbedtls_pk_context pk;
    mbedtls_ecdh_context ecdh;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    char pers[32];
    unsigned char shared_secret[64];

    srand(time(NULL) * time(NULL));
    snprintf(pers, sizeof(pers), "cecies_PERS_#!$\\+@100%d", get_random_pers_int());

    mbedtls_pk_init(&pk);
    mbedtls_ecdh_init(&ecdh);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, sizeof pers);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_pk_parse_public_key(&pk, public_key, public_key_length+1);

    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_pk_parse_public_key returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_CURVE448);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecp_group_load returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_mpi_lset(&ecdh.Qp.Z, 1);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_lset returned %d\n", ret);
        goto exit;
    }

    //ret = mbedtls_mpi_read_binary(&ecdh.Qp.X, srv_to_cli, sizeof(srv_to_cli));
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecdh_compute_shared(&ecdh.grp, &ecdh.z, &ecdh.Qp, &ecdh.d, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_mpi_write_binary(&ecdh.z, shared_secret, sizeof(shared_secret));
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret);
        goto exit;
    }

    ret = 0;

exit:

    mbedtls_ecdh_free(&ecdh);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return (ret);
}
