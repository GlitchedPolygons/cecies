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
    int r = 1;

    if (output_bufsize < cecies_calc_output_buffer_needed_size(data_length))
    {
        fprintf(stderr, "CECIES encryption failed: output buffer too small!\n");
        return CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
    }

    mbedtls_aes_context aes;
    mbedtls_ecp_group ecp_group;
    mbedtls_ecp_point aes_key_ecp;
    mbedtls_ecp_point public_key_ecp;
    mbedtls_ecp_point ephemeral_key_public;
    mbedtls_mpi ephemeral_key_private;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_md_context_t md_context;

    mbedtls_aes_init(&aes);
    mbedtls_ecp_group_init(&ecp_group);
    mbedtls_ecp_point_init(&aes_key_ecp);
    mbedtls_ecp_point_init(&public_key_ecp);
    mbedtls_ecp_point_init(&ephemeral_key_public);
    mbedtls_mpi_init(&ephemeral_key_private);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_md_init(&md_context);

    unsigned char iv[16];
    unsigned char salt[32];
    unsigned char aes_key[32];
    unsigned char aes_key_base[256];
    unsigned char ephemeral_key_public_bytes[256];
    size_t ephemeral_key_public_bytes_length = 0, aes_key_base_length = 0;

    memset(iv, 0x00, 16);
    memset(salt, 0x00, 32);
    memset(aes_key, 0x00, 32);
    memset(aes_key_base, 0x00, sizeof(aes_key_base));
    memset(ephemeral_key_public_bytes, 0x00, sizeof(ephemeral_key_public_bytes));

    unsigned char pers[32];
    snprintf((char*)pers, sizeof(pers), "cecies_PERS_#!$\\+@23%llu", cecies_get_random_12digit_integer());

    r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, sizeof(pers));
    if (r != 0)
    {
        fprintf(stderr, "MbedTLS PRNG seed failed! mbedtls_ctr_drbg_seed returned %d\n", r);
        goto exit;
    }

    r = mbedtls_ecp_group_load(&ecp_group, MBEDTLS_ECP_DP_CURVE448);
    if (r != 0)
    {
        fprintf(stderr, "MbedTLS ECP group setup failed! mbedtls_ecp_group_load returned %d\n", r);
        goto exit;
    }

    r = mbedtls_ecp_gen_keypair(&ecp_group, &ephemeral_key_private, &ephemeral_key_public, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (r != 0)
    {
        fprintf(stderr, "Ephemeral keypair generation failed! mbedtls_ecp_gen_keypair returned %d\n", r);
        goto exit;
    }

    r = mbedtls_ecp_check_privkey(&ecp_group, &ephemeral_key_private);
    if (r != 0)
    {
        fprintf(stderr, "Ephemeral private key invalid! mbedtls_ecp_check_privkey returned %d\n", r);
        goto exit;
    }

    r = mbedtls_ecp_check_pubkey(&ecp_group, &ephemeral_key_public);
    if (r != 0)
    {
        fprintf(stderr, "Ephemeral public key invalid! mbedtls_ecp_check_pubkey returned %d\n", r);
        goto exit;
    }

    size_t public_key_bytes_length;
    unsigned char public_key_bytes[64];
    if (public_key_base64)
    {
        r = mbedtls_base64_decode(public_key_bytes, sizeof(public_key_bytes), &public_key_bytes_length, public_key, public_key_length);
        if (r != 0)
        {
            fprintf(stderr, "Parsing recipient's public key failed! mbedtls_base64_decode returned %d\n", r);
            goto exit;
        }
    }
    else
    {
        memcpy(public_key_bytes, public_key, public_key_bytes_length = public_key_length);
    }

    r = mbedtls_ecp_point_read_binary(&ecp_group, &public_key_ecp, public_key_bytes, public_key_bytes_length);
    if (r != 0)
    {
        fprintf(stderr, "Parsing recipient's public key failed! mbedtls_ecp_point_read_binary returned %d\n", r);
        goto exit;
    }

    r = mbedtls_ecp_check_pubkey(&ecp_group, &public_key_ecp);
    if (r != 0)
    {
        fprintf(stderr, "Recipient public key invalid! mbedtls_ecp_check_pubkey returned %d\n", r);
        goto exit;
    }

    r = mbedtls_ecp_mul(&ecp_group, &aes_key_ecp, &ephemeral_key_private, &public_key_ecp, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (r != 0)
    {
        fprintf(stderr, "ECP scalar multiplication failed! mbedtls_ecp_mul returned %d\n", r);
        goto exit;
    }

    r = mbedtls_ecp_point_write_binary(&ecp_group, &aes_key_ecp, MBEDTLS_ECP_PF_COMPRESSED, &aes_key_base_length, aes_key_base, sizeof(aes_key_base));
    if (r != 0)
    {
        fprintf(stderr, "ECIES encryption failed! mbedtls_ecp_point_write_binary returned %d\n", r);
        goto exit;
    }

    r = mbedtls_ecp_point_write_binary(&ecp_group, &ephemeral_key_public, MBEDTLS_ECP_PF_COMPRESSED, &ephemeral_key_public_bytes_length, ephemeral_key_public_bytes, sizeof(ephemeral_key_public_bytes));
    if (r != 0)
    {
        fprintf(stderr, "ECIES encryption failed! mbedtls_ecp_point_write_binary returned %d\n", r);
        goto exit;
    }

    r = mbedtls_ctr_drbg_random(&ctr_drbg, salt, 32);
    if (r != 0 || memcmp(salt, empty32, 32) == 0)
    {
        fprintf(stderr, "Salt generation failed! mbedtls_ctr_drbg_random returned %d\n", r);
        goto exit;
    }

    r = mbedtls_ctr_drbg_random(&ctr_drbg, iv, 16);
    if (r != 0 || memcmp(iv, empty32, 16) == 0)
    {
        fprintf(stderr, "IV generation failed! mbedtls_ctr_drbg_random returned %d\n", r);
        goto exit;
    }

    r = mbedtls_md_setup(&md_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 0);
    if (r != 0)
    {
        fprintf(stderr, "MbedTLS MD context (SHA512) setup failed! mbedtls_md_setup returned %d\n", r);
        goto exit;
    }

    r = mbedtls_pkcs5_pbkdf2_hmac(&md_context, aes_key_base, sizeof(aes_key_base), salt, 32, 16384, 32, aes_key);
    if (r != 0 || memcmp(aes_key, empty32, 32) == 0)
    {
        fprintf(stderr, "PBKDF2 failed! mbedtls_pkcs5_pbkdf2_hmac returned %d\n", r);
        goto exit;
    }

    r = mbedtls_aes_setkey_enc(&aes, aes_key, 256);
    if (r != 0)
    {
        fprintf(stderr, "AES key setup failed! mbedtls_aes_setkey_enc returned %d\n", r);
        goto exit;
    }

    memcpy(output, iv, 16);
    memcpy(output + 16, salt, 32);

    r = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, cecies_calc_aes_cbc_ciphertext_length(data_length), iv, data, output + (sizeof(unsigned char) * 48));
    if (r != 0)
    {
        fprintf(stderr, "AES-CBC encryption failed! mbedtls_aes_crypt_cbc returned %d\n", r);
        goto exit;
    }

    // TODO: write ephemeral_key_public_bytes into output ciphertext
    // TODO: check if ephemeral_key_public_bytes_length is always the same

exit:

    mbedtls_aes_free(&aes);
    mbedtls_ecp_group_free(&ecp_group);
    mbedtls_ecp_point_free(&aes_key_ecp);
    mbedtls_ecp_point_free(&public_key_ecp);
    mbedtls_ecp_point_free(&ephemeral_key_public);
    mbedtls_mpi_free(&ephemeral_key_private);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_md_free(&md_context);

    memset(iv, 0x00, sizeof(iv));
    memset(salt, 0x00, sizeof(salt));
    memset(pers, 0x00, sizeof(pers));
    memset(aes_key, 0x00, sizeof(aes_key));
    memset(aes_key_base, 0x00, sizeof(aes_key_base));
    memset(ephemeral_key_public_bytes, 0x00, sizeof(ephemeral_key_public_bytes));

    return (r);
}
