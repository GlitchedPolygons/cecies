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
        fprintf(stdout, "ecdsa_sha256_secp256k1_verify:  Verify a secp256k1 signature using a specific public key. Call this program using exactly 3 arguments;  the FIRST one being the PUBLIC KEY (hex-string), the SECOND one being the SIGNATURE to verify (also a hex-string) and the THIRD one the actual STRING TO VERIFY the signature against.\n");
        return 0;
    }

    if (argc != 4)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_verify: wrong argument count. Check out \"ecdsa_sha256_secp256k1_verify --help\" for more details about how to use this!\n");
        return -1;
    }

    int ret = -10;
    size_t signature_len, public_key_len;

    unsigned char public_key[128];
    memset(public_key, 0x00, sizeof(public_key));

    unsigned char signature[128];
    memset(signature, 0x00, sizeof(signature));

    unsigned char sha256[32];
    memset(sha256, 0x00, sizeof(sha256));

    const char* public_key_hexstr = argv[1];
    const size_t public_key_hexstr_len = strlen(public_key_hexstr);

    const char* signature_hexstr = argv[2];
    const size_t signature_hexstr_len = strlen(signature_hexstr);

    const char* message = argv[3];
    const size_t message_len = strlen(message);

    if (public_key_hexstr_len != 130)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_verify: Invalid public key format/length!\n");
        return -2;
    }

    mbedtls_ecdsa_context ecdsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecdsa_init(&ecdsa);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char*)argv[0], strlen(argv[0]));
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_verify failed: \"mbedtls_ctr_drbg_seed\" returned: %d\n", ret);
        goto exit;
    }

    ret = cecies_hexstr2bin(public_key_hexstr, public_key_hexstr_len, public_key, sizeof(public_key), &public_key_len);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_verify failed: \"cecies_hexstr2bin\" returned: %d\n", ret);
        goto exit;
    }

    ret = cecies_hexstr2bin(signature_hexstr, signature_hexstr_len, signature, sizeof(signature), &signature_len);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_verify failed: \"cecies_hexstr2bin\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_sha256_ret((unsigned char*)message, message_len, sha256, 0);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_verify failed: \"mbedtls_sha256_ret\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256K1);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_verify failed: \"mbedtls_ecp_group_load\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q, public_key, public_key_len);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_verify failed: \"mbedtls_ecp_point_read_binary\" returned: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecdsa_read_signature(&ecdsa, sha256, sizeof(sha256), signature, signature_len);
    if (ret != 0)
    {
        fprintf(stderr, "ecdsa_sha256_secp256k1_verify failed: \"mbedtls_ecdsa_read_signature\" returned: %d\n", ret);
        goto exit;
    }

    fprintf(stdout, "ecdsa_sha256_secp256k1_verify: signature valid!\n");

exit:
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    memset(public_key, 0x00, sizeof(public_key));
    memset(signature, 0x00, sizeof(signature));
    memset(sha256, 0x00, sizeof(sha256));
    return ret;
}
