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

#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>
#include <mbedtls/ctr_drbg.h>
#include "cecies/encrypt.h"

int cecies_encrypt(const unsigned char* data, const size_t data_length, const unsigned char* public_key, const size_t public_key_length, unsigned char* output, const size_t output_bufsize, size_t* output_length)
{
    int ret = 1;
    mbedtls_ecdh_context ctx_cli;
    mbedtls_ecdh_context ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char cli_to_srv[32], srv_to_cli[32];
    const char pers[] = "cecies_PERS_#!$\\+@100";

    mbedtls_ecdh_init(&ctx_cli);
    mbedtls_ecdh_init(&ctx_srv);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    /*
     * Initialize random number generation
     */
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, sizeof pers);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    /*
     * Client: initialize context and generate keypair
     */
    ret = mbedtls_ecp_group_load(&ctx_cli.grp, MBEDTLS_ECP_DP_CURVE448);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecp_group_load returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public(&ctx_cli.grp, &ctx_cli.d, &ctx_cli.Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_mpi_write_binary(&ctx_cli.Q.X, cli_to_srv, 32);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret);
        goto exit;
    }

    /*
     * Server: initialize context and generate keypair
     */
    ret = mbedtls_ecp_group_load(&ctx_srv.grp, MBEDTLS_ECP_DP_CURVE448);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecp_group_load returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public(&ctx_srv.grp, &ctx_srv.d, &ctx_srv.Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_mpi_write_binary(&ctx_srv.Q.X, srv_to_cli, 32);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret);
        goto exit;
    }

    /*
     * Server: read peer's key and generate shared secret
     */
    ret = mbedtls_mpi_lset(&ctx_srv.Qp.Z, 1);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_lset returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_mpi_read_binary(&ctx_srv.Qp.X, cli_to_srv, 32);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecdh_compute_shared(&ctx_srv.grp, &ctx_srv.z, &ctx_srv.Qp, &ctx_srv.d, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret);
        goto exit;
    }

    /*
     * Client: read peer's key and generate shared secret
     */
    ret = mbedtls_mpi_lset(&ctx_cli.Qp.Z, 1);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_lset returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_mpi_read_binary(&ctx_cli.Qp.X, srv_to_cli, 32);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecdh_compute_shared(&ctx_cli.grp, &ctx_cli.z, &ctx_cli.Qp, &ctx_cli.d, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret);
        goto exit;
    }

    /*
     * Verification: are the computed secrets equal?
     */
    ret = mbedtls_mpi_cmp_mpi(&ctx_cli.z, &ctx_srv.z);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret);
        goto exit;
    }

    ret = 0;

exit:

    mbedtls_ecdh_free(&ctx_srv);
    mbedtls_ecdh_free(&ctx_cli);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return (ret);
}
