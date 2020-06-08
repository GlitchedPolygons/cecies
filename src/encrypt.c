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
#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md_internal.h>

#include "cecies/util.h"
#include "cecies/encrypt.h"

static const unsigned char empty32[32] = {
    //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
};

int cecies_encrypt(const unsigned char* data, const size_t data_length, const unsigned char* public_key, const size_t public_key_length, const bool public_key_base64, unsigned char* output, const size_t output_bufsize, size_t* output_length)
{
    int ret = 1;

    const size_t output_len = cecies_calc_output_buffer_needed_size(data_length);

    if (output_bufsize < output_len)
    {
        fprintf(stderr, "CECIES encryption failed: output buffer too small!\n");
        return CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
    }

    mbedtls_aes_context aes_ctx;
    mbedtls_ecp_group ecp_group;
    mbedtls_md_context_t md_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // Variables named after the ECIES illustration on https://asecuritysite.com/encryption/go_ecies
    mbedtls_mpi r;
    mbedtls_ecp_point R;
    mbedtls_ecp_point S;
    mbedtls_ecp_point QA;

    mbedtls_aes_init(&aes_ctx);
    mbedtls_ecp_group_init(&ecp_group);
    mbedtls_md_init(&md_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&r);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&S);
    mbedtls_ecp_point_init(&QA);

    unsigned char iv[16];
    unsigned char salt[32];
    unsigned char aes_key[32];
    unsigned char S_bytes[256];
    unsigned char R_bytes[256];
    size_t R_bytes_length = 0, S_bytes_length = 0;

    memset(iv, 0x00, 16);
    memset(salt, 0x00, 32);
    memset(aes_key, 0x00, 32);
    memset(S_bytes, 0x00, sizeof(S_bytes));
    memset(R_bytes, 0x00, sizeof(R_bytes));

    unsigned char pers[32];
    snprintf((char*)pers, sizeof(pers), "cecies_PERS_#!$\\+@23%llu", cecies_get_random_12digit_integer());

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

    ret = mbedtls_ecp_gen_keypair(&ecp_group, &r, &R, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        fprintf(stderr, "Ephemeral keypair generation failed! mbedtls_ecp_gen_keypair returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_check_privkey(&ecp_group, &r);
    if (ret != 0)
    {
        fprintf(stderr, "Ephemeral private key invalid! mbedtls_ecp_check_privkey returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_check_pubkey(&ecp_group, &R);
    if (ret != 0)
    {
        fprintf(stderr, "Ephemeral public key invalid! mbedtls_ecp_check_pubkey returned %d\n", ret);
        goto exit;
    }

    size_t public_key_bytes_length;
    unsigned char public_key_bytes[128];

    if (public_key_base64)
    {
        ret = mbedtls_base64_decode(public_key_bytes, sizeof(public_key_bytes), &public_key_bytes_length, public_key, public_key_length);
        if (ret != 0)
        {
            fprintf(stderr, "Parsing recipient's public key failed! mbedtls_base64_decode returned %d\n", ret);
            goto exit;
        }
    }
    else
    {
        memcpy(public_key_bytes, public_key, public_key_bytes_length = public_key_length);
    }

    ret = mbedtls_ecp_point_read_binary(&ecp_group, &QA, public_key_bytes, public_key_bytes_length);
    if (ret != 0)
    {
        fprintf(stderr, "Parsing recipient's public key failed! mbedtls_ecp_point_read_binary returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_check_pubkey(&ecp_group, &QA);
    if (ret != 0)
    {
        fprintf(stderr, "Recipient public key invalid! mbedtls_ecp_check_pubkey returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_mul(&ecp_group, &S, &r, &QA, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        fprintf(stderr, "ECP scalar multiplication failed! mbedtls_ecp_mul returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_point_write_binary(&ecp_group, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &S_bytes_length, S_bytes, sizeof(S_bytes));
    if (ret != 0)
    {
        fprintf(stderr, "ECIES encryption failed! mbedtls_ecp_point_write_binary returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_point_write_binary(&ecp_group, &R, MBEDTLS_ECP_PF_UNCOMPRESSED, &R_bytes_length, R_bytes, sizeof(R_bytes));
    if (ret != 0)
    {
        fprintf(stderr, "ECIES encryption failed! mbedtls_ecp_point_write_binary returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, salt, 32);
    if (ret != 0 || memcmp(salt, empty32, 32) == 0)
    {
        fprintf(stderr, "Salt generation failed! mbedtls_ctr_drbg_random returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv, 16);
    if (ret != 0 || memcmp(iv, empty32, 16) == 0)
    {
        fprintf(stderr, "IV generation failed! mbedtls_ctr_drbg_random returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1);
    if (ret != 0)
    {
        fprintf(stderr, "MbedTLS MD context (SHA512) setup failed! mbedtls_md_setup returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, S_bytes, S_bytes_length, salt, 32, 16384, 32, aes_key);
    if (ret != 0 || memcmp(aes_key, empty32, 32) == 0)
    {
        fprintf(stderr, "PBKDF2 failed! mbedtls_pkcs5_pbkdf2_hmac returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 256);
    if (ret != 0)
    {
        fprintf(stderr, "AES key setup failed! mbedtls_aes_setkey_enc returned %d\n", ret);
        goto exit;
    }

    const size_t ctlen = cecies_calc_aes_cbc_ciphertext_length(data_length);

    ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, ctlen, iv, data, output);
    if (ret != 0)
    {
        fprintf(stderr, "AES-CBC encryption failed! mbedtls_aes_crypt_cbc returned %d\n", ret);
        goto exit;
    }

    memcpy(output + ctlen, iv, 16);
    memcpy(output + ctlen + 16, salt, 32);
    memcpy(output + ctlen + 16 + 32, R_bytes, R_bytes_length);

    *output_length = output_len;

exit:

    mbedtls_aes_free(&aes_ctx);
    mbedtls_ecp_group_free(&ecp_group);
    mbedtls_md_free(&md_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&S);
    mbedtls_ecp_point_free(&QA);

    memset(iv, 0x00, sizeof(iv));
    memset(salt, 0x00, sizeof(salt));
    memset(pers, 0x00, sizeof(pers));
    memset(aes_key, 0x00, sizeof(aes_key));
    memset(S_bytes, 0x00, sizeof(S_bytes));
    memset(R_bytes, 0x00, sizeof(R_bytes));

    return (ret);
}
