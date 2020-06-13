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

static void cecies_printvoid_returns_0(void** state)
{
    assert_int_equal(0, cecies_printvoid(stderr, "void", 4));
}

static void cecies_fprintf_enables_and_disables_correctly(void** state)
{
    cecies_disable_fprintf();
    assert_false(cecies_is_fprintf_enabled());
    assert_memory_not_equal(_cecies_fprintf_fptr, &fprintf, sizeof(&fprintf));

    cecies_enable_fprintf();
    assert_true(cecies_is_fprintf_enabled());
    assert_memory_equal(_cecies_fprintf_fptr, &fprintf, sizeof(&fprintf));
}

static void cecies_hexstr2bin_invalid_args_returns_1(void** state)
{
    char hex[] = "90b008b752871710f032e58396eb75ead53b4abd83e074a855e8ca4c5fef4de7bb5e6a191cc10132466dbaee16a031c0046ce38535b8f922b93edd5e"
                 "429bcae7d715820107304e8e62818280cf643434e307d85dd659245e9a5588d93c5b62f34713e00b22d5c531f544de2b81879248b3d4e9b1160a60b9"
                 "b9670ff48a474c53057a02eeeefbbf16e384a252773502c2bc0a6c3f9831d20e2406a1f099567cab66cf7d61e8520995f3efecc0cfc0a4c667fdf0df"
                 "a5a4c56217e541ad4141642b00eab1095ad84721baac4fc9d9b86e47782e5ebc3d238885e4068ecea40ee2736aff024d5f4da58962b236b7c576ed57"
                 "1b9e3a0fb9ecfd9f877a530d11beecba0f938853c7dadde5";

    unsigned char bin[1024];
    size_t binlen;

    assert_int_equal(1, cecies_hexstr2bin(NULL, 0, NULL, 0, NULL));
    assert_int_equal(1, cecies_hexstr2bin(hex, 0, bin, sizeof(bin), NULL));
    assert_int_equal(1, cecies_hexstr2bin(NULL, 20, bin, sizeof(bin), NULL));
    assert_int_equal(1, cecies_hexstr2bin(hex, sizeof(hex), NULL, 0, &binlen));
}

static void cecies_hexstr2bin_hexlen_odd_number_fails_returns_2(void** state)
{
    char hex[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

    unsigned char bin[128];
    size_t binlen;

    assert_int_equal(2, cecies_hexstr2bin(hex, strlen(hex) - 1, bin, sizeof(bin), &binlen));
    assert_int_equal(2, cecies_hexstr2bin(hex, sizeof(hex) - 2, bin, sizeof(bin), &binlen));
}

static void cecies_hexstr2bin_insufficient_output_buffer_size_fails_returns_3(void** state)
{
    char hex[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

    unsigned char bin[1024];
    size_t binlen;

    assert_int_equal(3, cecies_hexstr2bin(hex, strlen(hex), bin, 32, &binlen));
    assert_int_equal(3, cecies_hexstr2bin(hex, strlen(hex), bin, strlen(hex) / 2, &binlen));
}

static void cecies_hexstr2bin_succeeds_both_with_and_without_nul_terminator(void** state)
{
    char hex[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

    unsigned char bin[1024];
    size_t binlen;

    assert_int_equal(0, cecies_hexstr2bin(hex, 112, bin, sizeof(bin), &binlen));
    assert_int_equal(0, cecies_hexstr2bin(hex, 113, bin, sizeof(bin), &binlen));
}

static void cecies_bin2hexstr_succeeds_output_length_double_the_input_length(void** state)
{
    unsigned char bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length;

    assert_int_equal(0, cecies_bin2hexstr(bin, sizeof(bin), hexstr, sizeof(hexstr), &hexstr_length, true));
    assert_int_equal(hexstr_length, sizeof(bin) * 2);
    assert_int_equal(hexstr[hexstr_length], '\0');
}

static void cecies_bin2hexstr_null_or_invalid_args_fails_returns_1(void** state)
{
    unsigned char bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length;

    assert_int_equal(1, cecies_bin2hexstr(NULL, sizeof(bin), hexstr, sizeof(hexstr), &hexstr_length, true));
    assert_int_equal(1, cecies_bin2hexstr(bin, 0, hexstr, sizeof(hexstr), &hexstr_length, true));
    assert_int_equal(1, cecies_bin2hexstr(bin, sizeof(bin), NULL, sizeof(hexstr), &hexstr_length, true));
}

static void cecies_bin2hexstr_insufficient_output_buffer_size_returns_2(void** state)
{
    unsigned char bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length;

    assert_int_equal(2, cecies_bin2hexstr(bin, sizeof(bin), hexstr, 6, &hexstr_length, true));

    // Double the size of the binary array should actually be enough,
    // but it's actually 1 byte too short: never forget to allocate +1 to allow for the NUL-terminator to fit in there!
    assert_int_equal(2, cecies_bin2hexstr(bin, sizeof(bin), hexstr, sizeof(bin) * 2, &hexstr_length, true));
}

static void cecies_bin2hexstr_success_returns_0(void** state)
{
    unsigned char bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length = 0;

    assert_int_equal(0, cecies_bin2hexstr(bin, sizeof(bin), hexstr, sizeof(hexstr), NULL, true));

    // If output length pointer arg is omitted (passed NULL), the variable should be left untouched indeed!
    assert_int_equal(hexstr_length, 0);

    assert_int_equal(0, cecies_bin2hexstr(bin, sizeof(bin), hexstr, (sizeof(bin) * 2) + 1, &hexstr_length, true));

    // output string is NUL-terminated (which is why (sizeof(bin) * 2) + 1 bytes need to be allocated), but the NUL-terminator is not counted in the output length.
    // The output length of a binary array converted to hex string is always sizeof(bin) * 2

    assert_int_equal(sizeof(bin) * 2, hexstr_length);
}

static void cecies_generate_curve448_keypair_NULL_args_return_CECIES_KEYGEN_ERROR_CODE_NULL_ARG(void** state)
{
    assert_int_equal(CECIES_KEYGEN_ERROR_CODE_NULL_ARG, cecies_generate_curve448_keypair(NULL, (unsigned char*)"test", 4));
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

static void cecies_generate_curve448_keypair_generated_keys_are_invalid(void** state)
{
    cecies_curve448_keypair keypair1;
    assert_int_equal(0, cecies_generate_curve448_keypair(&keypair1, (unsigned char*)"test test test", 14));

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
    prvkey1_decoded_bytes[0] = 0x9;
    prvkey1_decoded_bytes[1] = 13;

    mbedtls_mpi_read_binary(&prvkey1, prvkey1_decoded_bytes, prvkey1_decoded_bytes_length);

    assert_int_not_equal(0, mbedtls_ecp_check_privkey(&ecp_group1, &prvkey1));

    size_t pubkey1_decoded_bytes_length;
    unsigned char pubkey1_decoded_bytes[113];

    cecies_hexstr2bin(keypair1.public_key, sizeof(keypair1.public_key), pubkey1_decoded_bytes, sizeof(pubkey1_decoded_bytes), &pubkey1_decoded_bytes_length);
    pubkey1_decoded_bytes[0] = 1;
    assert_int_not_equal(0, mbedtls_ecp_point_read_binary(&ecp_group1, &pubkey1, pubkey1_decoded_bytes, 113));
    assert_int_not_equal(0, mbedtls_ecp_check_pubkey(&ecp_group1, &pubkey1));

    mbedtls_mpi_free(&prvkey1);
    mbedtls_ecp_point_free(&pubkey1);
    mbedtls_ecp_group_free(&ecp_group1);
}

static const char TEST_STRING[263] = "Still, I am not one to squander my investments... and I remain confident she was worth far more than the initial.. .appraisal. That's why I must now extract from you some small repayment owed for your own survival. See her safely to White Forest, Doctor Freeman!";

static const size_t TEST_STRING_LENGTH_WITH_NUL_TERMINATOR = 263;
static const size_t TEST_STRING_LENGTH_WITHOUT_NUL_TERMINATOR = 262;

static const char TEST_PUBLIC_KEY[] = "04ebf5be2d15c7fb53ff38a5759f78f2d87d77f0d243374ad1cceae84a7dc1d50ef5acda5b7b7359d49b7457e8537277e78ace1db6ca363221";

static const char TEST_PRIVATE_KEY[] = "dbee49abcf57dc0e2eb3b35ff00860fa683e0ac725c9e5d576340724f4894fac85730c93f688cbad98f98516d27e255ffeffd2365563cf24";

#define CECIES_TESTS_PBKDF2_ITERATIONS (1024 * 32)

static void cecies_encrypt_raw_binary_decrypts_successfully(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(0, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, encrypted_string_length, NULL, false));

    decrypted_string = malloc(encrypted_string_length);
    memset(decrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(0, cecies_decrypt(encrypted_string, encrypted_string_length, false, TEST_PRIVATE_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, decrypted_string, encrypted_string_length, &decrypted_string_length));
    assert_int_equal(0, memcmp(TEST_STRING, decrypted_string, decrypted_string_length));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_encrypt_base64_decrypts_successfully(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(0, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, encrypted_string_length, NULL, true));

    decrypted_string = malloc(encrypted_string_length);
    memset(decrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(0, cecies_decrypt(encrypted_string, encrypted_string_length, true, TEST_PRIVATE_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, decrypted_string, encrypted_string_length, &decrypted_string_length));
    assert_int_equal(0, memcmp(TEST_STRING, decrypted_string, decrypted_string_length));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_encrypt_bin_decrypt_with_public_key_fails(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(0, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, encrypted_string_length, NULL, false));

    decrypted_string = malloc(encrypted_string_length);
    memset(decrypted_string, 0x00, encrypted_string_length);

    assert_int_not_equal(0, cecies_decrypt(encrypted_string, encrypted_string_length, false, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, decrypted_string, encrypted_string_length, &decrypted_string_length));
    assert_int_not_equal(0, memcmp(TEST_STRING, decrypted_string, decrypted_string_length));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static const char INVALID_KEY[] = "Just something that isn't quite a key..";

static void cecies_encrypt_bin_decrypt_with_invalid_key_fails(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(0, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, encrypted_string_length, NULL, false));

    decrypted_string = malloc(encrypted_string_length);
    memset(decrypted_string, 0x00, encrypted_string_length);

    assert_int_not_equal(0, cecies_decrypt(encrypted_string, encrypted_string_length, false, INVALID_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, decrypted_string, encrypted_string_length, &decrypted_string_length));
    assert_int_not_equal(0, memcmp(TEST_STRING, decrypted_string, decrypted_string_length));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static const char INVALID_KEY2[] = "Just something that isn't quite a key... At least this one has the same length as a key would be of this size ;D";

static void cecies_encrypt_bin_decrypt_with_invalid_key_2_fails(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(0, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, encrypted_string_length, NULL, false));

    decrypted_string = malloc(encrypted_string_length);
    memset(decrypted_string, 0x00, encrypted_string_length);

    assert_int_not_equal(0, cecies_decrypt(encrypted_string, encrypted_string_length, false, INVALID_KEY2, CECIES_TESTS_PBKDF2_ITERATIONS, decrypted_string, encrypted_string_length, &decrypted_string_length));
    assert_int_not_equal(0, memcmp(TEST_STRING, decrypted_string, decrypted_string_length));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static const char TEST_PUBLIC_KEY2[] = "0450430325551ee86a6d9216947b5bdf04314771028e847029def87eb18474e10dcd981d72a2f51eff20ac1c1a3375850e0e53f1b065923304";

static const char TEST_PRIVATE_KEY2[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

static void cecies_encrypt_bin_decrypt_with_wrong_key_fails(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(0, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, encrypted_string_length, NULL, false));

    decrypted_string = malloc(encrypted_string_length);
    memset(decrypted_string, 0x00, encrypted_string_length);

    assert_int_not_equal(0, cecies_decrypt(encrypted_string, encrypted_string_length, false, TEST_PRIVATE_KEY2, CECIES_TESTS_PBKDF2_ITERATIONS, decrypted_string, encrypted_string_length, &decrypted_string_length));
    assert_int_not_equal(0, memcmp(TEST_STRING, decrypted_string, decrypted_string_length));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_encrypt_insufficient_pbkdf2_rounds_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_PBKDF2_ITERATIONS(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_PBKDF2_ITERATIONS, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, 1024 * 16, encrypted_string, encrypted_string_length, NULL, false));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_encrypt_null_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_NULL_ARG(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(CECIES_ENCRYPT_ERROR_CODE_NULL_ARG, cecies_encrypt(NULL, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, encrypted_string_length, NULL, false));
    assert_int_equal(CECIES_ENCRYPT_ERROR_CODE_NULL_ARG, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, NULL, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, encrypted_string_length, NULL, false));
    assert_int_equal(CECIES_ENCRYPT_ERROR_CODE_NULL_ARG, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, NULL, encrypted_string_length, NULL, false));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_encrypt_invalid_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG, cecies_encrypt((unsigned char*)TEST_STRING, 0, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, encrypted_string_length, NULL, false));
    assert_int_equal(CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, 0, NULL, false));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_encrypt_insufficient_output_buffer_size_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    assert_int_equal(CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, 32, NULL, false));

    // Take care with the NUL-terminators and choose how to handle those and STICK TO IT consistently. Look at how mixing it up can end up in a failure:
    assert_int_equal(CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, TEST_STRING_LENGTH_WITHOUT_NUL_TERMINATOR, NULL, false));

    // Also: when tired, worn out and/or not careful, it can happen that you use sizeof(some_pointer) because you thought it was an array/stack-allocated but instead you're just returning the size of the pointer. Happens all the time! Careful though, it causes a failure:
    assert_int_equal(CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, sizeof(encrypted_string), NULL, false));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_encrypt_output_length_always_identical_with_calculated_prediction(void** state)
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = cecies_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    size_t written_bytes;
    assert_int_equal(0, cecies_encrypt((unsigned char*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, TEST_PUBLIC_KEY, CECIES_TESTS_PBKDF2_ITERATIONS, encrypted_string, encrypted_string_length, &written_bytes, false));
    assert_int_equal(written_bytes, encrypted_string_length);

    free(encrypted_string);
    free(decrypted_string);
}

// --------------------------------------------------------------------------------------------------------------

int main(void)
{
    cecies_disable_fprintf();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(cecies_printvoid_returns_0),
        cmocka_unit_test(cecies_fprintf_enables_and_disables_correctly),
        cmocka_unit_test(cecies_hexstr2bin_invalid_args_returns_1),
        cmocka_unit_test(cecies_hexstr2bin_hexlen_odd_number_fails_returns_2),
        cmocka_unit_test(cecies_hexstr2bin_insufficient_output_buffer_size_fails_returns_3),
        cmocka_unit_test(cecies_hexstr2bin_succeeds_both_with_and_without_nul_terminator),
        cmocka_unit_test(cecies_bin2hexstr_succeeds_output_length_double_the_input_length),
        cmocka_unit_test(cecies_bin2hexstr_null_or_invalid_args_fails_returns_1),
        cmocka_unit_test(cecies_bin2hexstr_insufficient_output_buffer_size_returns_2),
        cmocka_unit_test(cecies_bin2hexstr_success_returns_0),
        cmocka_unit_test(cecies_generate_curve448_keypair_NULL_args_return_CECIES_KEYGEN_ERROR_CODE_NULL_ARG),
        cmocka_unit_test(cecies_generate_curve448_keypair_generated_keys_are_valid),
        cmocka_unit_test(cecies_generate_curve448_keypair_generated_keys_are_invalid),
        cmocka_unit_test(cecies_encrypt_raw_binary_decrypts_successfully),
        cmocka_unit_test(cecies_encrypt_base64_decrypts_successfully),
        cmocka_unit_test(cecies_encrypt_bin_decrypt_with_public_key_fails),
        cmocka_unit_test(cecies_encrypt_bin_decrypt_with_invalid_key_fails),
        cmocka_unit_test(cecies_encrypt_bin_decrypt_with_invalid_key_2_fails),
        cmocka_unit_test(cecies_encrypt_bin_decrypt_with_wrong_key_fails),
        cmocka_unit_test(cecies_encrypt_insufficient_pbkdf2_rounds_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_PBKDF2_ITERATIONS),
        cmocka_unit_test(cecies_encrypt_null_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_NULL_ARG),
        cmocka_unit_test(cecies_encrypt_invalid_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG),
        cmocka_unit_test(cecies_encrypt_insufficient_output_buffer_size_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE),
        cmocka_unit_test(cecies_encrypt_output_length_always_identical_with_calculated_prediction),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
