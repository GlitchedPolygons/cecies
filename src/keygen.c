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

#include <string.h>

#include <mbedtls/ecdh.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha512.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/platform_util.h>

#include "cecies/guid.h"
#include "cecies/keygen.h"

#include "cecies/data.txt"

int cecies_generate_curve25519_keypair(cecies_curve25519_keypair* output, const uint8_t* additional_entropy, const size_t additional_entropy_length)
{
    if (output == NULL)
    {
        cecies_fprintf(stderr, "\nCECIES: Key generation failed because the output argument was NULL!");
        return CECIES_KEYGEN_ERROR_CODE_NULL_ARG;
    }

    int ret = 1;

    mbedtls_ecp_group ecp_group;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi r;
    mbedtls_ecp_point R;

    mbedtls_ecp_group_init(&ecp_group);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&r);
    mbedtls_ecp_point_init(&R);

    uint8_t prvkeybuf[32] = { 0x00 };
    uint8_t pubkeybuf[32] = { 0x00 };
    size_t prvkeybuflen = 0, pubkeybuflen = 0;

    uint8_t pers[256];
    cecies_dev_urandom(pers, sizeof(pers));

    if (additional_entropy)
    {
        mbedtls_sha512_ret(additional_entropy, additional_entropy_length, pers + (sizeof(pers) - 64), 0);
    }
    else
    {
        char tmp[128];
        snprintf(tmp, 128, "%llu-cecies_PERS_@67\\##.<?@_<96-/%s", cecies_get_random_big_integer(), (uint8_t*)cecies_new_guid(1, 1).string);
        mbedtls_sha512_ret((unsigned char*)tmp, 128, pers + (sizeof(pers) - 64), 0);
    }

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, CECIES_MIN(sizeof(pers), (MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - MBEDTLS_CTR_DRBG_ENTROPY_LEN - 1)));
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: MbedTLS PRNG seed failed! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_group_load(&ecp_group, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: MbedTLS ECP group setup failed! mbedtls_ecp_group_load returned %d\n", ret);
        goto exit;
    }

    // Generate EC key-pair.

    ret = mbedtls_ecp_gen_keypair(&ecp_group, &r, &R, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Keypair generation failed! mbedtls_ecp_gen_keypair returned %d\n", ret);
        goto exit;
    }

    // Write private key into temporary buffer.

    ret = mbedtls_mpi_write_binary(&r, prvkeybuf, sizeof(prvkeybuf));
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Writing generated private key into temporary buffer failed! mbedtls_mpi_write_binary returned %d\n", ret);
        goto exit;
    }

    prvkeybuflen = mbedtls_mpi_size(&r);

    if (prvkeybuflen != sizeof(prvkeybuf))
    {
        cecies_fprintf(stderr, "\nCECIES: Invalid key length!");
        ret = -1;
        goto exit;
    }

    // Write public key into temporary buffer.

    ret = mbedtls_ecp_point_write_binary(&ecp_group, &R, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkeybuflen, pubkeybuf, sizeof(pubkeybuf));
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Writing generated public key into temporary buffer failed! mbedtls_ecp_point_write_binary returned %d\n", ret);
        goto exit;
    }

    if (pubkeybuflen != sizeof(pubkeybuf) || memcmp(pubkeybuf, empty256, sizeof(pubkeybuf)) == 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Public key has invalid format!\n");
        goto exit;
    }

    // Write keys out into their output buffer.

    ret = cecies_bin2hexstr(prvkeybuf, prvkeybuflen, output->private_key.hexstring, sizeof(output->private_key.hexstring), NULL, 0);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Writing generated private key into hex string output buffer failed! cecies_bin2hexstr returned %d\n", ret);
        goto exit;
    }

    ret = cecies_bin2hexstr(pubkeybuf, pubkeybuflen, output->public_key.hexstring, sizeof(output->public_key.hexstring), NULL, 0);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Writing generated public key into hex string output buffer failed! cecies_bin2hexstr returned %d\n", ret);
        goto exit;
    }

exit:

    mbedtls_ecp_group_free(&ecp_group);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&R);

    mbedtls_platform_zeroize(pers, sizeof(pers));
    mbedtls_platform_zeroize(prvkeybuf, sizeof(prvkeybuf));
    mbedtls_platform_zeroize(pubkeybuf, sizeof(pubkeybuf));

    return (ret);
}

int cecies_generate_curve448_keypair(cecies_curve448_keypair* output, const uint8_t* additional_entropy, const size_t additional_entropy_length)
{
    if (output == NULL)
    {
        cecies_fprintf(stderr, "\nCECIES: Key generation failed because the output argument was NULL!");
        return CECIES_KEYGEN_ERROR_CODE_NULL_ARG;
    }

    int ret = 1;

    mbedtls_ecp_group ecp_group;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi r;
    mbedtls_ecp_point R;

    mbedtls_ecp_group_init(&ecp_group);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&r);
    mbedtls_ecp_point_init(&R);

    uint8_t prvkeybuf[56] = { 0x00 };
    uint8_t pubkeybuf[56] = { 0x00 };
    size_t prvkeybuflen = 0, pubkeybuflen = 0;

    uint8_t pers[256];
    cecies_dev_urandom(pers, sizeof(pers));

    if (additional_entropy)
    {
        mbedtls_sha512_ret(additional_entropy, additional_entropy_length, pers + (sizeof(pers) - 64), 0);
    }
    else
    {
        char tmp[128];
        snprintf(tmp, 128, "%llu-cecies_PERS_#!.$\\+;@58-/%s", cecies_get_random_big_integer(), (uint8_t*)cecies_new_guid(1, 1).string);
        mbedtls_sha512_ret((unsigned char*)tmp, 128, pers + (sizeof(pers) - 64), 0);
    }

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, CECIES_MIN(sizeof(pers), (MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - MBEDTLS_CTR_DRBG_ENTROPY_LEN - 1)));
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: MbedTLS PRNG seed failed! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_group_load(&ecp_group, MBEDTLS_ECP_DP_CURVE448);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: MbedTLS ECP group setup failed! mbedtls_ecp_group_load returned %d\n", ret);
        goto exit;
    }

    // Generate EC key-pair.

    ret = mbedtls_ecp_gen_keypair(&ecp_group, &r, &R, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Keypair generation failed! mbedtls_ecp_gen_keypair returned %d\n", ret);
        goto exit;
    }

    // Write private key into temporary buffer.

    ret = mbedtls_mpi_write_binary(&r, prvkeybuf, sizeof(prvkeybuf));
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Writing generated private key into temporary buffer failed! mbedtls_mpi_write_binary returned %d\n", ret);
        goto exit;
    }

    prvkeybuflen = mbedtls_mpi_size(&r);

    if (prvkeybuflen != sizeof(prvkeybuf))
    {
        cecies_fprintf(stderr, "\nCECIES: Invalid key length!");
        ret = -1;
        goto exit;
    }

    // Write public key into temporary buffer.

    ret = mbedtls_ecp_point_write_binary(&ecp_group, &R, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkeybuflen, pubkeybuf, sizeof(pubkeybuf));
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Writing generated public key into temporary buffer failed! mbedtls_ecp_point_write_binary returned %d\n", ret);
        goto exit;
    }

    if (pubkeybuflen != sizeof(pubkeybuf) || memcmp(pubkeybuf, empty256, sizeof(pubkeybuf)) == 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Public key has invalid format!\n");
        goto exit;
    }

    // Write keys out into their output buffer.

    ret = cecies_bin2hexstr(prvkeybuf, prvkeybuflen, output->private_key.hexstring, sizeof(output->private_key.hexstring), NULL, 0);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Writing generated private key into hex string output buffer failed! cecies_bin2hexstr returned %d\n", ret);
        goto exit;
    }

    ret = cecies_bin2hexstr(pubkeybuf, pubkeybuflen, output->public_key.hexstring, sizeof(output->public_key.hexstring), NULL, 0);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "\nCECIES: Writing generated public key into hex string output buffer failed! cecies_bin2hexstr returned %d\n", ret);
        goto exit;
    }

exit:

    mbedtls_ecp_group_free(&ecp_group);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&R);

    mbedtls_platform_zeroize(pers, sizeof(pers));
    mbedtls_platform_zeroize(prvkeybuf, sizeof(prvkeybuf));
    mbedtls_platform_zeroize(pubkeybuf, sizeof(pubkeybuf));

    return (ret);
}