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
#include <stdbool.h>
#include <string.h>

#include <mbedtls/gcm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md_internal.h>

#include "cecies/util.h"
#include "cecies/decrypt.h"

static int cecies_decrypt(unsigned char* encrypted_data, const size_t encrypted_data_length, const bool encrypted_data_base64, const char* private_key, unsigned char* output, const size_t output_bufsize, size_t* output_length, const unsigned char curve)
{
    const size_t min_data_len = curve == 0 ? 97 : 121;
    const size_t key_length = curve == 0 ? CECIES_X25519_KEY_SIZE : CECIES_X448_KEY_SIZE;

    if (encrypted_data == NULL || output == NULL || output_length == NULL)
    {
        cecies_fprintf(stderr, "CECIES: decryption failed: one or more NULL arguments.\n");
        return CECIES_DECRYPT_ERROR_CODE_NULL_ARG;
    }

    if (encrypted_data_length < min_data_len || output_bufsize == 0)
    {
        cecies_fprintf(stderr, "CECIES: decryption failed: one or more invalid arguments.\n");
        return CECIES_DECRYPT_ERROR_CODE_INVALID_ARG;
    }

    int ret = 1;
    unsigned char* input = encrypted_data;
    size_t input_length = encrypted_data_length;

    if (encrypted_data_base64)
    {
        input = malloc(input_length);
        if (input == NULL)
        {
            cecies_fprintf(stderr, "CECIES: decryption failed: OUT OF MEMORY!\n");
            return CECIES_DECRYPT_ERROR_CODE_OUT_OF_MEMORY;
        }

        if (encrypted_data[input_length - 1] == '\0')
        {
            input_length--;
        }

        ret = mbedtls_base64_decode(input, input_length, &input_length, encrypted_data, input_length);
        if (ret != 0)
        {
            free(input);
            cecies_fprintf(stderr, "CECIES: decryption failed: couldn't base64-decode the given data! mbedtls_base64_decode returned %d\n", ret);
            return CECIES_DECRYPT_ERROR_CODE_INVALID_ARG;
        }
    }

    const size_t olen = input_length - 16 - 32 - key_length - 16;

    if (output_bufsize < olen)
    {
        cecies_fprintf(stderr, "CECIES: decryption failed due to insufficient output buffer size. Please allocate at least as many bytes as the encrypted input buffer, just to be sure!\n");
        return CECIES_DECRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
    }

    unsigned char iv[16];
    unsigned char tag[16];
    unsigned char salt[32];
    unsigned char aes_key[32];
    unsigned char R_bytes[64];
    unsigned char S_bytes[64];
    unsigned char private_key_bytes[64];
    size_t private_key_bytes_length, S_bytes_length;

    memset(iv, 0x00, 16);
    memset(tag, 0x00, 16);
    memset(salt, 0x00, 32);
    memset(aes_key, 0x00, 32);
    memset(R_bytes, 0x00, sizeof(R_bytes));
    memset(S_bytes, 0x00, sizeof(S_bytes));
    memset(private_key_bytes, 0x00, sizeof(private_key_bytes));

    mbedtls_ecp_group ecp_group;
    mbedtls_gcm_context aes_ctx;
    mbedtls_md_context_t md_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // Variables named after the ECIES illustration on https://asecuritysite.com/encryption/go_ecies
    mbedtls_mpi dA;
    mbedtls_ecp_point R;
    mbedtls_ecp_point S;

    mbedtls_ecp_group_init(&ecp_group);
    mbedtls_gcm_init(&aes_ctx);
    mbedtls_md_init(&md_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&dA);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&S);

    ret = mbedtls_ecp_group_load(&ecp_group, curve == 0 ? MBEDTLS_ECP_DP_CURVE25519 : MBEDTLS_ECP_DP_CURVE448);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: MbedTLS ECP group setup failed! mbedtls_ecp_group_load returned %d\n", ret);
        goto exit;
    }

    unsigned char pers[256];
    cecies_dev_urandom(pers, 128);
    snprintf((char*)(pers + 128), 128, "cecies_PERS_3~£,@+14/\\%llu", cecies_get_random_big_integer());

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, CECIES_MIN(sizeof(pers), (MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - MBEDTLS_CTR_DRBG_ENTROPY_LEN - 1)));
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: MbedTLS PRNG seed failed! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    memcpy(iv, input, 16);
    memcpy(salt, input + 16, 32);
    memcpy(R_bytes, input + 16 + 32, key_length);
    memcpy(tag, input + 16 + 32 + key_length, 16);

    const unsigned char* ciphertext = input + (16 + 32 + key_length + 16);

    ret = cecies_hexstr2bin(private_key, key_length * 2, private_key_bytes, sizeof(private_key_bytes), &private_key_bytes_length);
    if (ret != 0 || private_key_bytes_length != key_length)
    {
        cecies_fprintf(stderr, "CECIES: Parsing decryption private key failed! Invalid hex string format or invalid key length... cecies_hexstr2bin returned %d\n", ret);
        ret = CECIES_DECRYPT_ERROR_CODE_INVALID_ARG;
        goto exit;
    }

    ret = mbedtls_mpi_read_binary(&dA, private_key_bytes, private_key_bytes_length);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: Parsing decryption private key failed! mbedtls_mpi_read_binary returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_check_privkey(&ecp_group, &dA);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: Invalid decryption private key! mbedtls_ecp_check_privkey returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_point_read_binary(&ecp_group, &R, R_bytes, key_length);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: Parsing ephemeral public key failed! mbedtls_ecp_point_read_binary returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_check_pubkey(&ecp_group, &R);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: Ephemeral public key invalid! mbedtls_ecp_check_pubkey returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_mul(&ecp_group, &S, &dA, &R, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: Ephemeral public key multiplication invalid; couldn't compute AES secret! mbedtls_ecp_mul returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_point_write_binary(&ecp_group, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &S_bytes_length, S_bytes, key_length);
    if (ret != 0 || S_bytes_length != key_length)
    {
        cecies_fprintf(stderr, "CECIES: decryption failed! Invalid ECP point; mbedtls_ecp_point_write_binary returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: MbedTLS MD context (SHA512) setup failed! mbedtls_md_setup returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), salt, 32, S_bytes, S_bytes_length, NULL, 0, aes_key, 32);
    if (ret != 0 || memcmp(aes_key, empty32, 32) == 0)
    {
        cecies_fprintf(stderr, "CECIES: HKDF failed! mbedtls_hkdf returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, aes_key, 256);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: AES key setup failed! mbedtls_gcm_setkey returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_gcm_auth_decrypt(&aes_ctx, olen, iv, 16, NULL, 0, tag, 16, ciphertext, output);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: decryption failed! mbedtls_gcm_auth_decrypt returned %d\n", ret);
        goto exit;
    }

    *output_length = (size_t)olen;

exit:

    mbedtls_ecp_group_free(&ecp_group);
    mbedtls_gcm_free(&aes_ctx);
    mbedtls_md_free(&md_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_mpi_free(&dA);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&S);

    memset(iv, 0x00, 16);
    memset(salt, 0x00, 32);
    memset(aes_key, 0x00, 32);
    memset(R_bytes, 0x00, sizeof(R_bytes));
    memset(S_bytes, 0x00, sizeof(S_bytes));
    memset(&private_key, 0x00, sizeof(private_key));
    memset(private_key_bytes, 0x00, sizeof(private_key_bytes));

    if (encrypted_data_base64)
    {
        free(input);
    }

    return (ret);
}

int cecies_curve25519_decrypt(unsigned char* encrypted_data, const size_t encrypted_data_length, const bool encrypted_data_base64, cecies_curve25519_key private_key, unsigned char* output, const size_t output_bufsize, size_t* output_length)
{
    return cecies_decrypt(encrypted_data, encrypted_data_length, encrypted_data_base64, private_key.hexstring, output, output_bufsize, output_length, 0);
}

int cecies_curve448_decrypt(unsigned char* encrypted_data, const size_t encrypted_data_length, const bool encrypted_data_base64, cecies_curve448_key private_key, unsigned char* output, const size_t output_bufsize, size_t* output_length)
{
    return cecies_decrypt(encrypted_data, encrypted_data_length, encrypted_data_base64, private_key.hexstring, output, output_bufsize, output_length, 1);
}