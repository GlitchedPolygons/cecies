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
#include <mbedtls/sha512.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>

#include <ccrush.h>

#include "cecies/util.h"
#include "cecies/encrypt.h"

#include "cecies/data.txt"

static inline int cecies_prepare_data(const uint8_t* data, const size_t data_length, const int compress, uint8_t** out_data, size_t* out_data_length)
{
    if (compress)
    {
        return ccrush_compress(data, data_length, 256, compress, out_data, out_data_length);
    }

    *out_data = (uint8_t*)data;
    *out_data_length = data_length;
    return 0;
}

/*
 * This avoids code duplication between the Curve25519 and Curve448 encryption variants (only key length and a few minor things differ).
 * The last "curve" argument determines which curve to use for encryption: pass 0 for Curve25519 and 1 for Curve448!
 */
static int cecies_encrypt(const uint8_t* data, const size_t data_length, const int compress, const char* public_key, uint8_t** output, size_t* output_length, const int output_base64, const int curve)
{
    if (data == NULL || output == NULL || output_length == NULL || public_key == NULL)
    {
        return CECIES_ENCRYPT_ERROR_CODE_NULL_ARG;
    }

    if (data_length == 0)
    {
        return CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG;
    }

    int ret = 1;

    size_t key_length;

    if (curve == 0)
    {
        key_length = CECIES_X25519_KEY_SIZE;
    }
    else if (curve == 1)
    {
        key_length = CECIES_X448_KEY_SIZE;
    }
    else if (curve == 2)
    {
        key_length = SECP256K1_PUB_KEY_SIZE;
    }

    uint8_t* input_data = NULL;
    size_t input_data_length = 0;

    ret = cecies_prepare_data(data, data_length, compress, &input_data, &input_data_length);
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: compression failed: ccrush return code %d\n", ret);
        return CECIES_ENCRYPT_ERROR_CODE_COMPRESSION_FAILED;
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

    uint8_t iv[16] = { 0x00 };
    uint8_t salt[32] = { 0x00 };
    uint8_t aes_key[32] = { 0x00 };
    uint8_t S_bytes[128] = { 0x00 };
    uint8_t R_bytes[128] = { 0x00 };

    size_t R_bytes_length = 0, S_bytes_length = 0;

    uint8_t pers[256];
    cecies_dev_urandom(pers, 128);
    snprintf((char*)(pers + 128), 128, "cecies_PERS_@&=/\\.*67%llu", cecies_get_random_big_integer());
    mbedtls_sha512(pers + 128, 128, pers + 128 + 64, 0);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, CECIES_MIN(sizeof(pers), (MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - MBEDTLS_CTR_DRBG_ENTROPY_LEN - 1)));
    if (ret != 0)
    {
        cecies_fprintf(stderr, "CECIES: MbedTLS PRNG seed failed! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_ecp_group_id id;

    if (curve == 0)
    {
        id = MBEDTLS_ECP_DP_CURVE25519;
    }
    else if (curve == 1)
    {
        id = MBEDTLS_ECP_DP_CURVE448;
    }
    else if (curve == 2)
    {
        id = MBEDTLS_ECP_DP_SECP256K1;
    }

    ret = mbedtls_ecp_group_load(&ecp_group, id);
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
    uint8_t public_key_bytes[128] = { 0x00 }; //! Allocate large enough buffer for hex to bin conversion.

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

    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), salt, CECIES_SALT_LEN, S_bytes, S_bytes_length, NULL, 0, aes_key, 32);
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

    size_t olen = cecies_calc_output_buffer_needed_size(input_data_length, key_length);

    uint8_t* o = malloc(olen);
    if (o == NULL)
    {
        ret = CECIES_ENCRYPT_ERROR_CODE_OUT_OF_MEMORY;
        goto exit;
    }

    memcpy(o, R_bytes, R_bytes_length);
    memcpy(o + CECIES_IV_POS(R_bytes_length), iv, CECIES_IV_LEN);
    memcpy(o + CECIES_SALT_POS(R_bytes_length), salt, CECIES_SALT_LEN);

    ret = mbedtls_gcm_crypt_and_tag(                //
        &aes_ctx,                                   // MbedTLS AES context pointer.
        MBEDTLS_GCM_ENCRYPT,                        // Encryption mode.
        input_data_length,                          // Input data length (or compressed input data length if compression is enabled).
        iv,                                         // The initialization vector.
        CECIES_IV_LEN,                              // Length of the IV.
        NULL,                                       // No additional data.
        0,                                          // ^
        input_data,                                 // The input data to encrypt (or compressed input data if compression is enabled).
        o + CECIES_CIPHER_TEXT_POS(R_bytes_length), // Where to write the encrypted output bytes into: this is offset so that the order of the ciphertext prefix IV + Salt + Ephemeral Key + Tag is skipped.
        CECIES_TAG_LEN,                             // Length of the authentication tag.
        o + CECIES_TAG_POS(R_bytes_length)          // Where to insert the tag bytes inside the output ciphertext.
    );

    if (ret != 0)
    {
        free(o);
        cecies_fprintf(stderr, "CECIES: AES-GCM encryption failed! mbedtls_gcm_crypt_and_tag returned %d\n", ret);
        goto exit;
    }

    if (output_base64)
    {
        size_t b64len = cecies_calc_base64_length(olen);
        uint8_t* b64 = malloc(b64len);
        if (b64 == NULL)
        {
            ret = CECIES_ENCRYPT_ERROR_CODE_OUT_OF_MEMORY;
            cecies_fprintf(stderr, "CECIES: AES-GCM encryption failed while base64-encoding the output - OUT OF MEMORY! \n");
            free(o);
            goto exit;
        }

        ret = mbedtls_base64_encode(b64, b64len, &b64len, o, olen);
        if (ret != 0)
        {
            cecies_fprintf(stderr, "CECIES: AES-GCM encryption failed while base64-encoding! mbedtls_base64_encode returned %d\n", ret);
            free(o);
            free(b64);
            goto exit;
        }

        free(o);
        *output = b64;
        *output_length = b64len;
        goto exit;
    }

    *output = o;
    *output_length = olen;

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

    if (compress && input_data != NULL)
    {
        mbedtls_platform_zeroize(input_data, input_data_length);
        free(input_data);
    }

    return (ret);
}

int cecies_curve25519_encrypt(const uint8_t* data, const size_t data_length, const int compress, const cecies_curve25519_key public_key, uint8_t** output, size_t* output_length, const int output_base64)
{
    return cecies_encrypt(data, data_length, compress, public_key.hexstring, output, output_length, output_base64, 0);
}

int cecies_curve448_encrypt(const uint8_t* data, const size_t data_length, const int compress, const cecies_curve448_key public_key, uint8_t** output, size_t* output_length, const int output_base64)
{
    return cecies_encrypt(data, data_length, compress, public_key.hexstring, output, output_length, output_base64, 1);
}

int cecies_secp256k1_encrypt(const uint8_t* data, const size_t data_length, const int compress, const cecies_SECP256K1_pub_key public_key, uint8_t** output, size_t* output_length, const int output_base64)
{
    return cecies_encrypt(data, data_length, compress, public_key.hexstring, output, output_length, output_base64, 2);
}
