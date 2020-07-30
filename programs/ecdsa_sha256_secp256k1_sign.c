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
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cecies/util.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

int main(int argc, const char* argv[])
{
    cecies_enable_fprintf();

    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        fprintf(stdout, "ecdsa_sha256_secp256k1_sign: Sign a string using SHA256 + ECDSA (over the secp256k1 curve). This program takes exactly 2 arguments: the first one being the private key with which to sign (hex-string), and the second one the message string that you want to sign.\n");
        return 0;
    }

    if (argc != 3)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_sign failed: wrong argument count. Check out \"ecdsa_sha256_secp256k1_sign --help\" for more details about how to use this!\n");
        return -1;
    }

    int ret = -10;

    const char* private_key_hexstr = argv[1];
    const char* message = argv[2];

    const size_t private_key_hexstr_len = strlen(private_key_hexstr);
    const size_t message_len = strlen(message);

    if (private_key_hexstr_len != 64)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_sign failed: Invalid secret key format/length!\n");
        return -2;
    }

    mbedtls_ecdsa_context ecdsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecdsa_init(&ecdsa);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    unsigned char sha256[32];
    memset(sha256, 0x00, sizeof(sha256));

    size_t signature_length;
    unsigned char signature[MBEDTLS_ECDSA_MAX_LEN];
    memset(signature, 0x00, sizeof(signature));

    unsigned char private_key[32 + 1];
    memset(private_key, 0x00, sizeof(private_key));

    ret = cecies_hexstr2bin(private_key_hexstr, 64, private_key, sizeof(private_key), NULL);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_sign failed: Invalid secret key format/length!\n");
        goto exit;
    }

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char*)argv[0], strlen(argv[0]));
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_sign failed: \"mbedtls_ctr_drbg_seed\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_mpi_read_binary(&ecdsa.d, private_key, 32);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_sign failed: \"mbedtls_mpi_read_binary\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_sha256_ret((unsigned char*)message, message_len, sha256, 0);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_sign failed: \"mbedtls_sha256_ret\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256K1);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_sign failed: \"mbedtls_ecp_group_load\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, sha256, 32, signature, &signature_length, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_sign failed: \"mbedtls_ecdsa_write_signature\" returned: %d\n", ret);
        goto exit;
    }

    for (int i = 0; i < signature_length; ++i)
    {
        fprintf(stdout, "%02x", signature[i]);
    }

    fprintf(stdout, "\n");

exit:
    // Cleanup:
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    memset(sha256, 0x00, sizeof(sha256));
    memset(signature, 0x00, sizeof(signature));
    memset(private_key, 0x00, sizeof(private_key));
    return ret;
}
