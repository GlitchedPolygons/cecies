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
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include <cmocka.h>

#include <mbedtls/gcm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md_internal.h>

#include <cecies/util.h>
#include <cecies/keygen.h>
#include <cecies/encrypt.h>
#include <cecies/decrypt.h>

/* A test case that does nothing and succeeds. */
static void null_test_success(void** state)
{
    (void)state;
}

static void cecies_generate_curve448_keypair_NULL_args_return_CECIES_KEYGEN_ERROR_CODE_NULL_ARG(void** state)
{
    assert_int_equal(CECIES_KEYGEN_ERROR_CODE_NULL_ARG, cecies_generate_curve448_keypair(NULL, (unsigned char*)"test", 4));
}

static void cecies_generate_curve448_keypair_invalid_args_return_CECIES_KEYGEN_ERROR_CODE_INVALID_ARG(void** state)
{
    cecies_curve448_keypair keypair;
    assert_int_equal(CECIES_KEYGEN_ERROR_CODE_INVALID_ARG, cecies_generate_curve448_keypair(&keypair, (unsigned char*)"test", 0));
}

static void cecies_generate_curve448_keypair_generated_keys_are_valid(void** state)
{
    cecies_curve448_keypair keypair1;
    assert_int_equal(0, cecies_generate_curve448_keypair(&keypair1, (unsigned char*)"testtesttest", 12));

    mbedtls_mpi prvkey1;
    mbedtls_mpi_init(&prvkey1);

    mbedtls_ecp_group ecp_group1;
    mbedtls_ecp_group_init(&ecp_group1);
    mbedtls_ecp_group_load(&ecp_group1, MBEDTLS_ECP_DP_CURVE448);

    mbedtls_ecp_point pubkey1;
    mbedtls_ecp_point_init(&pubkey1);

    size_t prvkey1_decoded_bytes_length;
    unsigned char prvkey1_decoded_bytes[256];

    cecies_hexstr2bin(keypair1.private_key, sizeof(keypair1.private_key), prvkey1_decoded_bytes, sizeof(prvkey1_decoded_bytes), &prvkey1_decoded_bytes_length);

    assert_int_equal(0, mbedtls_mpi_read_binary(&prvkey1, prvkey1_decoded_bytes, prvkey1_decoded_bytes_length));
    assert_int_equal(0, mbedtls_ecp_check_privkey(&ecp_group1, &prvkey1));

    size_t pubkey1_decoded_bytes_length;
    unsigned char pubkey1_decoded_bytes[113];

    cecies_hexstr2bin(keypair1.public_key, sizeof(keypair1.public_key), pubkey1_decoded_bytes, sizeof(pubkey1_decoded_bytes), &pubkey1_decoded_bytes_length);

    assert_int_equal(57, pubkey1_decoded_bytes_length);
    assert_int_equal(0, mbedtls_ecp_point_read_binary(&ecp_group1, &pubkey1, pubkey1_decoded_bytes, 113));
    assert_int_equal(0, mbedtls_ecp_check_pubkey(&ecp_group1, &pubkey1));

    mbedtls_mpi_free(&prvkey1);
    mbedtls_ecp_point_free(&pubkey1);
    mbedtls_ecp_group_free(&ecp_group1);

    // Test without additional entropy.

    cecies_curve448_keypair keypair2;
    assert_int_equal(0, cecies_generate_curve448_keypair(&keypair2, NULL, 0));

    mbedtls_mpi prvkey2;
    mbedtls_mpi_init(&prvkey2);

    mbedtls_ecp_group ecp_group2;
    mbedtls_ecp_group_init(&ecp_group2);
    mbedtls_ecp_group_load(&ecp_group2, MBEDTLS_ECP_DP_CURVE448);

    mbedtls_ecp_point pubkey2;
    mbedtls_ecp_point_init(&pubkey2);

    size_t prvkey2_decoded_bytes_length;
    unsigned char prvkey2_decoded_bytes[256];

    cecies_hexstr2bin(keypair2.private_key, sizeof(keypair2.private_key), prvkey2_decoded_bytes, sizeof(prvkey2_decoded_bytes), &prvkey2_decoded_bytes_length);

    assert_int_equal(0, mbedtls_mpi_read_binary(&prvkey2, prvkey2_decoded_bytes, prvkey2_decoded_bytes_length));
    assert_int_equal(0, mbedtls_ecp_check_privkey(&ecp_group2, &prvkey2));

    size_t pubkey2_decoded_bytes_length;
    unsigned char pubkey2_decoded_bytes[113];

    cecies_hexstr2bin(keypair2.public_key, sizeof(keypair2.public_key), pubkey2_decoded_bytes, sizeof(pubkey2_decoded_bytes), &pubkey2_decoded_bytes_length);

    assert_int_equal(57, pubkey2_decoded_bytes_length);
    assert_int_equal(0, mbedtls_ecp_point_read_binary(&ecp_group2, &pubkey2, pubkey2_decoded_bytes, 113));
    assert_int_equal(0, mbedtls_ecp_check_pubkey(&ecp_group2, &pubkey2));

    mbedtls_mpi_free(&prvkey2);
    mbedtls_ecp_point_free(&pubkey2);
    mbedtls_ecp_group_free(&ecp_group2);
}

// --------------------------------------------------------------------------------------------------------------

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(cecies_generate_curve448_keypair_NULL_args_return_CECIES_KEYGEN_ERROR_CODE_NULL_ARG),
        cmocka_unit_test(cecies_generate_curve448_keypair_invalid_args_return_CECIES_KEYGEN_ERROR_CODE_INVALID_ARG),
        cmocka_unit_test(cecies_generate_curve448_keypair_generated_keys_are_valid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
