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
#include <mbedtls/gcm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md_internal.h>

#include "cecies/util.h"
#include "cecies/encrypt.h"

/*
 * This avoids code duplication between the Curve25519 and Curve448 encryption variants (only key length and a few minor things differ).
 * The last "curve" argument determines which curve to use for encryption: pass 0 for Curve25519 and 1 for Curve448!
 */
static int cecies_encrypt(const unsigned char* data, const size_t data_length, const char* public_key, unsigned char* output, const size_t output_bufsize, size_t* output_length, const bool output_base64, const unsigned char curve)
{
    if (data == NULL || output == NULL)
    {
        return CECIES_ENCRYPT_ERROR_CODE_NULL_ARG;
    }

    if (data_length == 0 || output_bufsize == 0)
    {
        return CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG;
    }

    int ret = 1;

    const size_t key_length = curve == 0 ? CECIES_X25519_KEY_SIZE : CECIES_X448_KEY_SIZE;

    size_t olen = cecies_calc_output_buffer_needed_size(data_length, key_length);
    size_t total_output_length = output_base64 ? cecies_calc_base64_length(olen) : olen;

    if (output_bufsize < total_output_length)
    {
        cecies_fprintf(stderr, "CECIES: encryption failed: output buffer too small!\n");
        return CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
    }

    mbedtls_gcm_context aes_ctx;
    mbedtls_ecp_group ecp_group;
    mbedtls_md_context_t md_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // Variables named after the ECIES illustration on https://asecuritysite.com/encryption/go_ecies
    mbedtls_mpi r;
    mbedtls_ecp_point R;
    mbedtls_ecp_point S;
    mbedtls_ecp_point QA;

    mbedtls_gcm_init(&aes_ctx);
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
    unsigned char S_bytes[128];
    unsigned char R_bytes[128];

    size_t R_bytes_length = 0, S_bytes_length = 0;

    memset(iv, 0x00, 16);
    memset(salt, 0x00, 32);
    memset(aes_key, 0x00, 32);
    memset(S_bytes, 0x00, sizeof(S_bytes));
    memset(R_bytes, 0x00, sizeof(R_bytes));

    unsigned char pers[256];
    cecies_dev_urandom(pers, 128);
    snprintf((char*)(pers + 128), 128, "cecies_PERS_@&=/\\.*67%llu", cecies_get_random_big_integer());

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, CECIES_MIN(sizeof(pers), (MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - MBEDTLS_CTR_DRBG_ENTROPY_LEN - 1)));
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: MbedTLS PRNG seed failed! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_group_load(&ecp_group, curve == 0 ? MBEDTLS_ECP_DP_CURVE25519 : MBEDTLS_ECP_DP_CURVE448);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: MbedTLS ECP group setup failed! mbedtls_ecp_group_load returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_gen_keypair(&ecp_group, &r, &R, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: Ephemeral keypair generation failed! mbedtls_ecp_gen_keypair returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_check_privkey(&ecp_group, &r);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: Ephemeral private key invalid! mbedtls_ecp_check_privkey returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_check_pubkey(&ecp_group, &R);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: Ephemeral public key invalid! mbedtls_ecp_check_pubkey returned %d\n", ret);
        goto exit;
    }

    size_t public_key_bytes_length;
    unsigned char public_key_bytes[64];
    memset(public_key_bytes, 0x00, sizeof(public_key_bytes));

    ret = cecies_hexstr2bin(public_key, key_length * 2, public_key_bytes, sizeof(public_key_bytes), &public_key_bytes_length);
    if (ret != 0 || public_key_bytes_length != key_length)
    {
        cecies_fprintf(stderr, "CECIES: Parsing recipient's public key failed! Invalid hex string format...\n");
        goto exit;
    }

    ret = mbedtls_ecp_point_read_binary(&ecp_group, &QA, public_key_bytes, public_key_bytes_length);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: Parsing recipient's public key failed! mbedtls_ecp_point_read_binary returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_check_pubkey(&ecp_group, &QA);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: Recipient public key invalid! mbedtls_ecp_check_pubkey returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_mul(&ecp_group, &S, &r, &QA, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: ECP scalar multiplication failed! mbedtls_ecp_mul returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_point_write_binary(&ecp_group, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &S_bytes_length, S_bytes, sizeof(S_bytes));
    if (ret != 0 || S_bytes_length != key_length)
    {
        cecies_fprintf(stderr, "CECIES: encryption failed! mbedtls_ecp_point_write_binary returned %d ; or incorrect ECP point binary length.\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_point_write_binary(&ecp_group, &R, MBEDTLS_ECP_PF_UNCOMPRESSED, &R_bytes_length, R_bytes, sizeof(R_bytes));
    if (ret != 0 || R_bytes_length != key_length)
    {
        cecies_fprintf(stderr, "CECIES: encryption failed! mbedtls_ecp_point_write_binary returned %d ; or incorrect ephemeral public key length written by mbedtls_ecp_point_write_binary function..\n", ret);
        goto exit;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, salt, 32);
    if (ret != 0 || memcmp(salt, empty32, 32) == 0)
    {
        cecies_fprintf(stderr, "CECIES: Salt generation failed! mbedtls_ctr_drbg_random returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv, 16);
    if (ret != 0 || memcmp(iv, empty32, 16) == 0)
    {
        cecies_fprintf(stderr, "CECIES: IV generation failed! mbedtls_ctr_drbg_random returned %d\n", ret);
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

    unsigned char* o = output;

    memcpy(o, iv, 16);
    o += 16;

    memcpy(o, salt, 32);
    o += 32;

    memcpy(o, R_bytes, R_bytes_length);
    o += R_bytes_length;

    ret = mbedtls_gcm_crypt_and_tag(&aes_ctx, MBEDTLS_GCM_ENCRYPT, data_length, iv, 16, NULL, 0, data, o + 16, 16, o);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: AES-GCM encryption failed! mbedtls_gcm_crypt_and_tag returned %d\n", ret);
        goto exit;
    }

    if (output_base64)
    {
        size_t b64len;
        unsigned char* b64 = malloc(total_output_length);
        if (b64 == NULL)
        {
            ret = CECIES_ENCRYPT_ERROR_CODE_OUT_OF_MEMORY;
            cecies_fprintf(stderr, "CECIES: AES-GCM encryption failed while base64-encoding the output - OUT OF MEMORY! \n");
            goto exit;
        }

        ret = mbedtls_base64_encode(b64, total_output_length, &b64len, output, olen);
        if (ret != 0)
        {
            cecies_fprintf(stderr, "CECIES: AES-GCM encryption failed while base64-encoding! mbedtls_base64_encode returned %d\n", ret);
            free(b64);
            goto exit;
        }

        b64[total_output_length - 1] = '\0';
        memcpy(output, b64, total_output_length--);
        free(b64);
    }

    if (output_length != NULL)
    {
        *output_length = total_output_length;
    }

exit:

    mbedtls_gcm_free(&aes_ctx);
    mbedtls_ecp_group_free(&ecp_group);
    mbedtls_md_free(&md_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&S);
    mbedtls_ecp_point_free(&QA);

    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(salt, sizeof(salt));
    mbedtls_platform_zeroize(pers, sizeof(pers));
    mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
    mbedtls_platform_zeroize(S_bytes, sizeof(S_bytes));
    mbedtls_platform_zeroize(R_bytes, sizeof(R_bytes));

    return (ret);
}

int cecies_curve25519_encrypt(const unsigned char* data, const size_t data_length, const cecies_curve25519_key public_key, unsigned char* output, const size_t output_bufsize, size_t* output_length, const bool output_base64)
{
    return cecies_encrypt(data, data_length, public_key.hexstring, output, output_bufsize, output_length, output_base64, 0);
}

int cecies_curve448_encrypt(const unsigned char* data, const size_t data_length, const cecies_curve448_key public_key, unsigned char* output, const size_t output_bufsize, size_t* output_length, const bool output_base64)
{
    return cecies_encrypt(data, data_length, public_key.hexstring, output, output_bufsize, output_length, output_base64, 1);
}
