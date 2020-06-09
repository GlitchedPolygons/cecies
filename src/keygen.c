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
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "cecies/util.h"
#include "cecies/keygen.h"

int cecies_generate_curve448_keypair(const bool base64, unsigned char* output_private_key_buffer, const size_t output_private_key_buffer_size, size_t* output_private_key_buffer_length, unsigned char* output_public_key_buffer, const size_t output_public_key_buffer_size, size_t* output_public_key_buffer_length, unsigned char* additional_entropy, const size_t additional_entropy_length)
{
    if (output_private_key_buffer == NULL //
            || output_private_key_buffer_length == NULL //
            || output_public_key_buffer == NULL //
            || output_public_key_buffer_length == NULL //
            || (additional_entropy_length && additional_entropy == NULL)) //
    {
        return CECIES_KEYGEN_ERROR_CODE_NULL_ARG;
    }

    if (output_private_key_buffer_size == 0 //
            || output_public_key_buffer_size == 0 //
            || (additional_entropy && additional_entropy_length == 0))
    {
        return CECIES_KEYGEN_ERROR_CODE_INVALID_ARG;
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

    unsigned char pers[32];
    unsigned char prvkeybuf[512];
    unsigned char pubkeybuf[512];
    size_t prvkeybuflen, pubkeybuflen;

    memset(prvkeybuf, 0x00, sizeof(prvkeybuf));
    memset(pubkeybuf, 0x00, sizeof(pubkeybuf));

    if (additional_entropy != NULL && additional_entropy_length > 0)
    {
        snprintf((char*)pers, sizeof(pers), "%llu%s", cecies_get_random_big_integer(), additional_entropy);
    }
    else
    {
        snprintf((char*)pers, sizeof(pers), "cecies_PERS_#!$\\+@74%llu", cecies_get_random_big_integer());
    }

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, sizeof(pers));
    if (ret != 0)
    {
        fprintf(stderr, "MbedTLS PRNG seed failed! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_group_load(&ecp_group, MBEDTLS_ECP_DP_CURVE448);
    if (ret != 0)
    {
        fprintf(stderr, "MbedTLS ECP group setup failed! mbedtls_ecp_group_load returned %d\n", ret);
        goto exit;
    }

    // Generate EC key-pair.

    ret = mbedtls_ecp_gen_keypair(&ecp_group, &r, &R, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        fprintf(stderr, "CECIES Keypair generation failed! mbedtls_ecp_gen_keypair returned %d\n", ret);
        goto exit;
    }

    // Write private key into temporary buffer.

    ret = mbedtls_mpi_write_binary(&r, prvkeybuf, sizeof(prvkeybuf));
    if (ret != 0)
    {
        fprintf(stderr, "Writing generated private key into temporary buffer failed! mbedtls_mpi_write_binary returned %d\n", ret);
        goto exit;
    }

    prvkeybuflen = mbedtls_mpi_size(&r);

    // Check private key output buffer size.

    if (output_private_key_buffer_size < (base64 ? cecies_calc_base64_length(prvkeybuflen) : prvkeybuflen))
    {
        ret = CECIES_KEYGEN_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
        fprintf(stderr, "Writing generated private key into output buffer failed because the buffer is too small! \n");
        goto exit;
    }

    // Write public key into temporary buffer.

    ret = mbedtls_ecp_point_write_binary(&ecp_group, &R, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkeybuflen, pubkeybuf, sizeof(pubkeybuf));
    if (ret != 0)
    {
        fprintf(stderr, "Writing generated public key into temporary buffer failed! mbedtls_ecp_point_write_binary returned %d\n", ret);
        goto exit;
    }

    // Check public key output buffer size.

    if (output_public_key_buffer_size < (base64 ? cecies_calc_base64_length(pubkeybuflen) : pubkeybuflen))
    {
        ret = CECIES_KEYGEN_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
        fprintf(stderr, "Writing generated public key into output buffer failed because the buffer is too small! \n");
        goto exit;
    }

    // Write keys out into their output buffer.

    if (base64)
    {
        ret = mbedtls_base64_encode(output_private_key_buffer, output_private_key_buffer_size, output_private_key_buffer_length, prvkeybuf + (sizeof(prvkeybuf) - prvkeybuflen), prvkeybuflen);
        if (ret != 0)
        {
            fprintf(stderr, "Writing generated public key into output buffer failed! mbedtls_ecp_point_write_binary returned %d\n", ret);
            goto exit;
        }

        ret = mbedtls_base64_encode(output_public_key_buffer, output_public_key_buffer_size, output_public_key_buffer_length, pubkeybuf, pubkeybuflen);
        if (ret != 0)
        {
            fprintf(stderr, "Writing generated public key into output buffer failed! mbedtls_ecp_point_write_binary returned %d\n", ret);
            goto exit;
        }
    }
    else
    {
        *output_private_key_buffer_length = prvkeybuflen;
        memcpy(output_private_key_buffer, prvkeybuf + (sizeof(prvkeybuf) - prvkeybuflen), prvkeybuflen);

        *output_public_key_buffer_length = pubkeybuflen;
        memcpy(output_public_key_buffer, pubkeybuf, pubkeybuflen);
    }

exit:

    mbedtls_ecp_group_free(&ecp_group);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&R);

    memset(pers, 0x00, sizeof(pers));
    memset(prvkeybuf, 0x00, sizeof(prvkeybuf));
    memset(pubkeybuf, 0x00, sizeof(pubkeybuf));

    return (ret);
}