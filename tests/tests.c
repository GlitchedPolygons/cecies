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

#include <mbedtls/gcm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md_internal.h>

#include <cecies/util.h>
#include <cecies/keygen.h>
#include <cecies/encrypt.h>
#include <cecies/decrypt.h>

#define TEST_INIT cecies_disable_fprintf()
#include <acutest.h>

/* A test case that does nothing and succeeds. */
static void null_test_success()
{
    TEST_CHECK(1);
}

static void cecies_printvoid_returns_0()
{
    TEST_CHECK(0 == cecies_printvoid(stderr, "void", strlen("void")));
}

// DISCLAIMER:  Coverage won't be 100% because MbedTLS return codes and failures won't be tested against. It just doesn't make sense: they are already tested by MbedTLS itself.

static void cecies_fprintf_enables_and_disables_correctly()
{
    cecies_disable_fprintf();
    TEST_CHECK(!cecies_is_fprintf_enabled());
    TEST_CHECK(memcmp(cecies_fprintf_fptr, &fprintf, sizeof(&fprintf)) != 0);

    cecies_enable_fprintf();
    TEST_CHECK(cecies_is_fprintf_enabled());
    TEST_CHECK(memcmp(cecies_fprintf_fptr, &fprintf, sizeof(&fprintf)) == 0);

    cecies_disable_fprintf();
}

static const char TEST_STRING[263] = "Still, I am not one to squander my investments... and I remain confident she was worth far more than the initial... appraisal. That's why I must now extract from you some small repayment owed for your own survival. See her safely to White Forest, Doctor Freeman!";

static const size_t TEST_STRING_LENGTH_WITH_NUL_TERMINATOR = 263;
static const size_t TEST_STRING_LENGTH_WITHOUT_NUL_TERMINATOR = 262;

static const cecies_curve25519_key TEST_CURVE25519_PUBLIC_KEY = { .hexstring = "87981c92ede838b434e5fcd9eec9cd45ceaade59f3b72bb9e2088927c50dee07" };
static const cecies_curve25519_key TEST_CURVE25519_PRIVATE_KEY = { .hexstring = "72dcda48cacaf2969d4faecdbdf1e080a269ccc3c4ce16238050fa95052ad110" };
static const cecies_curve25519_key TEST_CURVE25519_PRIVATE_KEY_INVALID_HEX = { .hexstring = "5435d9e5c5zzzd8ayyy33b7a53844bad6e76c345363648c03f676c6f0f457690" };

static const cecies_curve448_key TEST_CURVE448_PUBLIC_KEY = { .hexstring = "fe8391ca7ad9ed36f524b9a481c5c36e0cfdd088b1113aca9a1e9569a49ee0296d2cd7c3b2a426651166e723a3f75c884b8be7dcefc1dd03" };
static const cecies_curve448_key TEST_CURVE448_PRIVATE_KEY = { .hexstring = "adc1b4fef09d3c22f183ba33a312609bb6d5cac77b3aa791081c6058e34369360968868648702c6a538c447a45b9ea889fa271b5a29e2ee4" };
static const cecies_curve448_key TEST_CURVE448_PRIVATE_KEY_INVALID_HEX = { .hexstring = "dbee49abcfpzqqik2eb3b35ff00860fa683e0ac725c9e5d576340724f4894fac85730c93f688cbad98f98516d27e255ffeffd2365563cf24" };

static void cecies_hexstr2bin_invalid_args_returns_1()
{
    char hex[] = "90b008b752871710f032e58396eb75ead53b4abd83e074a855e8ca4c5fef4de7bb5e6a191cc10132466dbaee16a031c0046ce38535b8f922b93edd5e"
                 "429bcae7d715820107304e8e62818280cf643434e307d85dd659245e9a5588d93c5b62f34713e00b22d5c531f544de2b81879248b3d4e9b1160a60b9"
                 "b9670ff48a474c53057a02eeeefbbf16e384a252773502c2bc0a6c3f9831d20e2406a1f099567cab66cf7d61e8520995f3efecc0cfc0a4c667fdf0df"
                 "a5a4c56217e541ad4141642b00eab1095ad84721baac4fc9d9b86e47782e5ebc3d238885e4068ecea40ee2736aff024d5f4da58962b236b7c576ed57"
                 "1b9e3a0fb9ecfd9f877a530d11beecba0f938853c7dadde5";

    uint8_t bin[1024];
    size_t binlen;

    TEST_CHECK(1 == cecies_hexstr2bin(NULL, 0, NULL, 0, NULL));
    TEST_CHECK(1 == cecies_hexstr2bin(hex, 0, bin, sizeof(bin), NULL));
    TEST_CHECK(1 == cecies_hexstr2bin(NULL, 20, bin, sizeof(bin), NULL));
    TEST_CHECK(1 == cecies_hexstr2bin(hex, sizeof(hex), NULL, 0, &binlen));
}

static void cecies_hexstr2bin_hexlen_odd_number_fails_returns_2()
{
    char hex[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

    uint8_t bin[128];
    size_t binlen;

    TEST_CHECK(2 == cecies_hexstr2bin(hex, strlen(hex) - 1, bin, sizeof(bin), &binlen));
    TEST_CHECK(2 == cecies_hexstr2bin(hex, sizeof(hex) - 2, bin, sizeof(bin), &binlen));
}

static void cecies_hexstr2bin_insufficient_output_buffer_size_fails_returns_3()
{
    char hex[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

    uint8_t bin[1024];
    size_t binlen;

    TEST_CHECK(3 == cecies_hexstr2bin(hex, strlen(hex), bin, 32, &binlen));
    TEST_CHECK(3 == cecies_hexstr2bin(hex, strlen(hex), bin, strlen(hex) / 2, &binlen));
}

static void cecies_hexstr2bin_succeeds_both_with_and_without_nul_terminator()
{
    char hex[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

    uint8_t bin[1024];
    size_t binlen;

    TEST_CHECK(0 == cecies_hexstr2bin(hex, 112, bin, sizeof(bin), &binlen));
    TEST_CHECK(0 == cecies_hexstr2bin(hex, 113, bin, sizeof(bin), &binlen));
}

static void cecies_bin2hexstr_succeeds_output_length_double_the_input_length()
{
    uint8_t bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length;

    TEST_CHECK(0 == cecies_bin2hexstr(bin, sizeof(bin), hexstr, sizeof(hexstr), &hexstr_length, 1));
    TEST_CHECK(hexstr_length == sizeof(bin) * 2);
    TEST_CHECK(hexstr[hexstr_length] == '\0');
}

static void cecies_bin2hexstr_null_or_invalid_args_fails_returns_1()
{
    uint8_t bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length;

    TEST_CHECK(1 == cecies_bin2hexstr(NULL, sizeof(bin), hexstr, sizeof(hexstr), &hexstr_length, 1));
    TEST_CHECK(1 == cecies_bin2hexstr(bin, 0, hexstr, sizeof(hexstr), &hexstr_length, 1));
    TEST_CHECK(1 == cecies_bin2hexstr(bin, sizeof(bin), NULL, sizeof(hexstr), &hexstr_length, 1));
}

static void cecies_bin2hexstr_insufficient_output_buffer_size_returns_2()
{
    uint8_t bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length;

    TEST_CHECK(2 == cecies_bin2hexstr(bin, sizeof(bin), hexstr, 6, &hexstr_length, 1));

    // Double the size of the binary array should actually be enough,
    // but it's actually 1 byte too short: never forget to allocate +1 to allow for the NUL-terminator to fit in there!
    TEST_CHECK(2 == cecies_bin2hexstr(bin, sizeof(bin), hexstr, sizeof(bin) * 2, &hexstr_length, 1));
}

static void cecies_bin2hexstr_success_returns_0()
{
    uint8_t bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length = 0;

    TEST_CHECK(0 == cecies_bin2hexstr(bin, sizeof(bin), hexstr, sizeof(hexstr), NULL, 1));

    // If output length pointer arg is omitted (passed NULL), the variable should be left untouched indeed!
    TEST_CHECK(hexstr_length == 0);

    TEST_CHECK(0 == cecies_bin2hexstr(bin, sizeof(bin), hexstr, (sizeof(bin) * 2) + 1, &hexstr_length, 1));

    // output string is NUL-terminated (which is why (sizeof(bin) * 2) + 1 bytes need to be allocated), but the NUL-terminator is not counted in the output length.
    // The output length of a binary array converted to hex string is always sizeof(bin) * 2

    TEST_CHECK(sizeof(bin) * 2 == hexstr_length);
}

// -----------------------------------------------------------------------------------------------------------------------     CURVE 25519

static void cecies_generate_curve25519_keypair_NULL_args_return_CECIES_KEYGEN_ERROR_CODE_NULL_ARG()
{
    TEST_CHECK(CECIES_KEYGEN_ERROR_CODE_NULL_ARG == cecies_generate_curve25519_keypair(NULL, (uint8_t*)"Lorem ipsum dolor sick fuck amend something something ...", 57));
}

static void cecies_generate_curve25519_keypair_generated_keys_are_valid()
{
    cecies_curve25519_keypair keypair1;
    TEST_CHECK(0 == cecies_generate_curve25519_keypair(&keypair1, (uint8_t*)"testtesttest", 12));

    mbedtls_mpi prvkey1;
    mbedtls_mpi_init(&prvkey1);

    mbedtls_ecp_group ecp_group1;
    mbedtls_ecp_group_init(&ecp_group1);
    mbedtls_ecp_group_load(&ecp_group1, MBEDTLS_ECP_DP_CURVE25519);

    mbedtls_ecp_point pubkey1;
    mbedtls_ecp_point_init(&pubkey1);

    size_t prvkey1_decoded_bytes_length;
    uint8_t prvkey1_decoded_bytes[256];

    cecies_hexstr2bin(keypair1.private_key.hexstring, sizeof(keypair1.private_key.hexstring), prvkey1_decoded_bytes, sizeof(prvkey1_decoded_bytes), &prvkey1_decoded_bytes_length);

    TEST_CHECK(0 == mbedtls_mpi_read_binary(&prvkey1, prvkey1_decoded_bytes, prvkey1_decoded_bytes_length));
    TEST_CHECK(0 == mbedtls_ecp_check_privkey(&ecp_group1, &prvkey1));

    size_t pubkey1_decoded_bytes_length;
    uint8_t pubkey1_decoded_bytes[65];
    memset(pubkey1_decoded_bytes, 0x00, sizeof(pubkey1_decoded_bytes));

    cecies_hexstr2bin(keypair1.public_key.hexstring, sizeof(keypair1.public_key.hexstring), pubkey1_decoded_bytes, sizeof(pubkey1_decoded_bytes), &pubkey1_decoded_bytes_length);

    TEST_CHECK(32 == pubkey1_decoded_bytes_length);
    TEST_CHECK(0 == mbedtls_ecp_point_read_binary(&ecp_group1, &pubkey1, pubkey1_decoded_bytes, pubkey1_decoded_bytes_length));
    TEST_CHECK(0 == mbedtls_ecp_check_pubkey(&ecp_group1, &pubkey1));

    mbedtls_mpi_free(&prvkey1);
    mbedtls_ecp_point_free(&pubkey1);
    mbedtls_ecp_group_free(&ecp_group1);

    // Test without additional entropy.

    cecies_curve25519_keypair keypair2;
    TEST_CHECK(0 == cecies_generate_curve25519_keypair(&keypair2, NULL, 0));

    mbedtls_mpi prvkey2;
    mbedtls_mpi_init(&prvkey2);

    mbedtls_ecp_group ecp_group2;
    mbedtls_ecp_group_init(&ecp_group2);
    mbedtls_ecp_group_load(&ecp_group2, MBEDTLS_ECP_DP_CURVE25519);

    mbedtls_ecp_point pubkey2;
    mbedtls_ecp_point_init(&pubkey2);

    size_t prvkey2_decoded_bytes_length;
    uint8_t prvkey2_decoded_bytes[256];

    cecies_hexstr2bin(keypair2.private_key.hexstring, sizeof(keypair2.private_key.hexstring), prvkey2_decoded_bytes, sizeof(prvkey2_decoded_bytes), &prvkey2_decoded_bytes_length);

    TEST_CHECK(0 == mbedtls_mpi_read_binary(&prvkey2, prvkey2_decoded_bytes, prvkey2_decoded_bytes_length));
    TEST_CHECK(0 == mbedtls_ecp_check_privkey(&ecp_group2, &prvkey2));

    size_t pubkey2_decoded_bytes_length;
    uint8_t pubkey2_decoded_bytes[65];
    cecies_hexstr2bin(keypair2.public_key.hexstring, sizeof(keypair2.public_key.hexstring), pubkey2_decoded_bytes, sizeof(pubkey2_decoded_bytes), &pubkey2_decoded_bytes_length);

    TEST_CHECK(32 == pubkey2_decoded_bytes_length);
    TEST_CHECK(0 == mbedtls_ecp_point_read_binary(&ecp_group2, &pubkey2, pubkey2_decoded_bytes, pubkey2_decoded_bytes_length));
    TEST_CHECK(0 == mbedtls_ecp_check_pubkey(&ecp_group2, &pubkey2));

    mbedtls_mpi_free(&prvkey2);
    mbedtls_ecp_point_free(&pubkey2);
    mbedtls_ecp_group_free(&ecp_group2);
}

static void cecies_generate_curve25519_keypair_generated_keys_are_invalid()
{
    cecies_curve25519_keypair keypair1;
    TEST_CHECK(0 == cecies_generate_curve25519_keypair(&keypair1, (uint8_t*)"test test test", 14));

    mbedtls_mpi prvkey1;
    mbedtls_mpi_init(&prvkey1);

    mbedtls_ecp_group ecp_group1;
    mbedtls_ecp_group_init(&ecp_group1);
    mbedtls_ecp_group_load(&ecp_group1, MBEDTLS_ECP_DP_CURVE25519);

    mbedtls_ecp_point pubkey1;
    mbedtls_ecp_point_init(&pubkey1);

    size_t prvkey1_decoded_bytes_length;
    uint8_t prvkey1_decoded_bytes[256];

    cecies_hexstr2bin(keypair1.private_key.hexstring, sizeof(keypair1.private_key.hexstring), prvkey1_decoded_bytes, sizeof(prvkey1_decoded_bytes), &prvkey1_decoded_bytes_length);
    prvkey1_decoded_bytes[0] = 0x9;
    prvkey1_decoded_bytes[1] = 13;

    mbedtls_mpi_read_binary(&prvkey1, prvkey1_decoded_bytes, prvkey1_decoded_bytes_length);

    TEST_CHECK(0 != mbedtls_ecp_check_privkey(&ecp_group1, &prvkey1));

    size_t pubkey1_decoded_bytes_length;
    uint8_t pubkey1_decoded_bytes[65];

    cecies_hexstr2bin(keypair1.public_key.hexstring, sizeof(keypair1.public_key.hexstring), pubkey1_decoded_bytes, sizeof(pubkey1_decoded_bytes), &pubkey1_decoded_bytes_length);
    pubkey1_decoded_bytes[0] = 1;
    TEST_CHECK(0 != mbedtls_ecp_point_read_binary(&ecp_group1, &pubkey1, pubkey1_decoded_bytes, 65));
    TEST_CHECK(0 != mbedtls_ecp_check_pubkey(&ecp_group1, &pubkey1));

    mbedtls_mpi_free(&prvkey1);
    mbedtls_ecp_point_free(&pubkey1);
    mbedtls_ecp_group_free(&ecp_group1);
}

static void cecies_generate_curve25519_keypair_with_way_too_much_additional_entropy_successful_nonetheless()
{
    cecies_curve25519_keypair keypair1;
    const char* additional_entropy = TEST_STRING;
    TEST_CHECK(0 == cecies_generate_curve25519_keypair(&keypair1, (uint8_t*)additional_entropy, strlen(additional_entropy)));

    mbedtls_mpi prvkey1;
    mbedtls_mpi_init(&prvkey1);

    mbedtls_ecp_group ecp_group1;
    mbedtls_ecp_group_init(&ecp_group1);
    mbedtls_ecp_group_load(&ecp_group1, MBEDTLS_ECP_DP_CURVE25519);

    mbedtls_ecp_point pubkey1;
    mbedtls_ecp_point_init(&pubkey1);

    size_t prvkey1_decoded_bytes_length;
    uint8_t prvkey1_decoded_bytes[256];

    cecies_hexstr2bin(keypair1.private_key.hexstring, sizeof(keypair1.private_key.hexstring), prvkey1_decoded_bytes, sizeof(prvkey1_decoded_bytes), &prvkey1_decoded_bytes_length);
    prvkey1_decoded_bytes[0] = 0x9;
    prvkey1_decoded_bytes[1] = 13;

    mbedtls_mpi_read_binary(&prvkey1, prvkey1_decoded_bytes, prvkey1_decoded_bytes_length);

    TEST_CHECK(0 != mbedtls_ecp_check_privkey(&ecp_group1, &prvkey1));

    size_t pubkey1_decoded_bytes_length;
    uint8_t pubkey1_decoded_bytes[65];

    cecies_hexstr2bin(keypair1.public_key.hexstring, sizeof(keypair1.public_key.hexstring), pubkey1_decoded_bytes, sizeof(pubkey1_decoded_bytes), &pubkey1_decoded_bytes_length);
    pubkey1_decoded_bytes[0] = 1;
    TEST_CHECK(0 != mbedtls_ecp_point_read_binary(&ecp_group1, &pubkey1, pubkey1_decoded_bytes, 65));
    TEST_CHECK(0 != mbedtls_ecp_check_pubkey(&ecp_group1, &pubkey1));

    mbedtls_mpi_free(&prvkey1);
    mbedtls_ecp_point_free(&pubkey1);
    mbedtls_ecp_group_free(&ecp_group1);
}

static void cecies_curve25519_encrypt_raw_binary_decrypts_successfully()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));
    TEST_CHECK(0 == cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &encrypted_string_length));
    TEST_CHECK(0 == memcmp(TEST_STRING, decrypted_string, sizeof(TEST_STRING)));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_raw_binary_with_zlib_header_but_no_comprssion_still_decrypts_successfully()
{
    // Encrypted data may also just happen to start with a valid zlib header but not be a zlib stream at all!

    uint8_t* encrypted_data = NULL;
    uint8_t* decrypted_data = NULL;
    size_t encrypted_data_length = 0;
    size_t decrypted_data_length = 0;

    //                              v     v    These first two bytes are a valid zlib header, but the rest is just not compressed data at all oh boy!
    const uint8_t test_data[] = { 0x78, 0x5E, 0x32, 0x55, 0x99, 0x11, 0xF4, 0x00, 0x22, 0x45, 0xBD, 0xDD };

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt(test_data, sizeof test_data, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_data, &encrypted_data_length, 0));
    TEST_CHECK(0 == cecies_curve25519_decrypt(encrypted_data, encrypted_data_length, 0, TEST_CURVE25519_PRIVATE_KEY, &decrypted_data, &decrypted_data_length));

    TEST_CHECK(decrypted_data_length == sizeof test_data);
    TEST_CHECK(0 == memcmp(test_data, decrypted_data, sizeof test_data));

    //

    free(encrypted_data);
    free(decrypted_data);
}

static void cecies_curve25519_encrypt_base64_decrypts_successfully()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve25519_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));
    TEST_CHECK(0 == cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(0 == memcmp(TEST_STRING, decrypted_string, sizeof(TEST_STRING)));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_bin_decrypt_with_public_key_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_ASSERT(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE25519_PUBLIC_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static const cecies_curve25519_key INVALID_CURVE25519_KEY = { .hexstring = "Just something that isn't quite a key..." };

static void cecies_curve25519_encrypt_bin_decrypt_with_invalid_key_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, INVALID_CURVE25519_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static const cecies_curve25519_key INVALID_CURVE25519_KEY2 = { .hexstring = "Just something that isn't quite a key.....  Maybe a smiley?  :D " };

static void cecies_curve25519_encrypt_bin_decrypt_with_invalid_key_2_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, INVALID_CURVE25519_KEY2, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static const cecies_curve25519_key TEST_CURVE25519_PUBLIC_KEY2 = { .hexstring = "3e16564a593738fd1c33fda2341e044a64513708dcbb73cea5eb78c2d6df365a" };

static const cecies_curve25519_key TEST_CURVE25519_PRIVATE_KEY2 = { .hexstring = "72250c5248fd1d9780126ee15f94dabcb0f3cb4622f9625f523a76d5884ffbb0" };

static void cecies_curve25519_encrypt_bin_decrypt_with_wrong_key_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE25519_PRIVATE_KEY2, &decrypted_string, &decrypted_string_length));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_bin_decrypt_with_zero_key_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    cecies_curve25519_key z = { .hexstring = "0000000000000000000000000000000000000000000000000000000000000000" };
    TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, z, &decrypted_string, &decrypted_string_length));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_bin_decrypt_with_NULL_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_NULL_ARG()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 == cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &encrypted_string_length));

    TEST_CHECK(CECIES_DECRYPT_ERROR_CODE_NULL_ARG == cecies_curve25519_decrypt(NULL, encrypted_string_length, 0, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(CECIES_DECRYPT_ERROR_CODE_NULL_ARG == cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE25519_PRIVATE_KEY, NULL, &decrypted_string_length));
    TEST_CHECK(CECIES_DECRYPT_ERROR_CODE_NULL_ARG == cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, NULL));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_bin_decrypt_with_INVALID_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(CECIES_DECRYPT_ERROR_CODE_INVALID_ARG == cecies_curve25519_decrypt(encrypted_string, 58, 0, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_base64_decrypt_invalid_base64_str_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve25519_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    TEST_CHECK(0 == cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(CECIES_DECRYPT_ERROR_CODE_INVALID_ARG == cecies_curve25519_decrypt((uint8_t*)"Definitively not a valid base64-encoded string! HJAB37GSVG37HJBSH83JBSH836TVSIV3663T7UV6TVSIV3663T7UVWGS87JBSH836TVSIV3663T7UV368736368", 135, 1, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_base64_decrypt_base64_with_or_without_NUL_terminator_both_succeeds()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));
    TEST_CHECK(encrypted_string_length == strlen((char*)encrypted_string));

    TEST_CHECK(encrypted_string[encrypted_string_length] == '\0');

    TEST_CHECK(0 == cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    free(decrypted_string);

    TEST_CHECK(0 == cecies_curve25519_decrypt(encrypted_string, encrypted_string_length + 1, 1, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    free(decrypted_string);
    free(encrypted_string);
}

static void cecies_curve25519_encrypt_null_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_NULL_ARG()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(CECIES_ENCRYPT_ERROR_CODE_NULL_ARG == cecies_curve25519_encrypt(NULL, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, NULL, 0));
    TEST_CHECK(CECIES_ENCRYPT_ERROR_CODE_NULL_ARG == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, NULL, NULL, 0));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_invalid_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, 0, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_base64_decrypt_base64_with_invalid_private_key_hex_format_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));
    TEST_CHECK(encrypted_string_length == strlen((char*)encrypted_string));

    TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE25519_PRIVATE_KEY_INVALID_HEX, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_base64_decrypt_different_key_always_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve25519_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    for (int i = 0; i < 64; ++i)
    {
        cecies_curve25519_keypair kp;
        cecies_generate_curve25519_keypair(&kp, (uint8_t*)"test test_*ç%°#@", 16);
        TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 1, kp.private_key, &decrypted_string, &encrypted_string_length));
    }

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_output_length_always_identical_with_calculated_prediction()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_curve25519_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);

    size_t written_bytes;
    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &written_bytes, 0));
    TEST_CHECK(written_bytes == encrypted_string_length);

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_base64_decrypt_base64_tampered_ephemeral_public_key_embedded_in_ciphertext_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve25519_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    encrypted_string[64] = 'L';
    encrypted_string[65] = 'O';
    encrypted_string[66] = 'L';

    TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_base64_decrypt_binary_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve25519_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &encrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_binary_decrypt_base64_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_base64_decrypt_ciphertext_was_tampered_with_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve25519_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    encrypted_string[200] = 'A';
    encrypted_string[201] = 'B';
    encrypted_string[202] = 'C';
    TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_binary_decrypt_ciphertext_was_tampered_with_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    encrypted_string[200] = 'A';
    encrypted_string[201] = 'B';
    encrypted_string[202] = 'C';
    TEST_CHECK(0 != cecies_curve25519_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &encrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_base64_decrypt_base64_lengths_identical()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));
    TEST_CHECK(encrypted_string_length == strlen((char*)encrypted_string));

    TEST_CHECK(0 == cecies_curve25519_decrypt(encrypted_string, encrypted_string_length + 1, 1, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR == decrypted_string_length);

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve25519_encrypt_base64_decrypt_base64_compression_reduces_size()
{
    char test_string[4096 * 2];
    for (int i = 0; i < sizeof test_string; ++i)
    {
        test_string[i] = TEST_STRING[i % (TEST_STRING_LENGTH_WITHOUT_NUL_TERMINATOR)];
    }

    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve25519_encrypt((uint8_t*)test_string, sizeof test_string, 9, TEST_CURVE25519_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));
    TEST_CHECK(encrypted_string_length < sizeof test_string);

    TEST_CHECK(0 == cecies_curve25519_decrypt(encrypted_string, encrypted_string_length + 1, 1, TEST_CURVE25519_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(sizeof test_string == decrypted_string_length);

    free(encrypted_string);
    free(decrypted_string);
}

// -----------------------------------------------------------------------------------------------------------------------     CURVE 448

static void cecies_generate_curve448_keypair_NULL_args_return_CECIES_KEYGEN_ERROR_CODE_NULL_ARG()
{
    TEST_CHECK(CECIES_KEYGEN_ERROR_CODE_NULL_ARG == cecies_generate_curve448_keypair(NULL, (uint8_t*)"test", 4));
}

static void cecies_generate_curve448_keypair_generated_keys_are_valid()
{
    cecies_curve448_keypair keypair1;
    TEST_CHECK(0 == cecies_generate_curve448_keypair(&keypair1, (uint8_t*)"Lorem ipsum dolor sick fuck amend something something ...", 57));

    mbedtls_mpi prvkey1;
    mbedtls_mpi_init(&prvkey1);

    mbedtls_ecp_group ecp_group1;
    mbedtls_ecp_group_init(&ecp_group1);
    mbedtls_ecp_group_load(&ecp_group1, MBEDTLS_ECP_DP_CURVE448);

    mbedtls_ecp_point pubkey1;
    mbedtls_ecp_point_init(&pubkey1);

    size_t prvkey1_decoded_bytes_length;
    uint8_t prvkey1_decoded_bytes[256];

    cecies_hexstr2bin(keypair1.private_key.hexstring, sizeof(keypair1.private_key.hexstring) - 1, prvkey1_decoded_bytes, sizeof(prvkey1_decoded_bytes), &prvkey1_decoded_bytes_length);

    TEST_CHECK(0 == mbedtls_mpi_read_binary(&prvkey1, prvkey1_decoded_bytes, prvkey1_decoded_bytes_length));
    TEST_CHECK(0 == mbedtls_ecp_check_privkey(&ecp_group1, &prvkey1));

    size_t pubkey1_decoded_bytes_length;
    uint8_t pubkey1_decoded_bytes[113];
    memset(pubkey1_decoded_bytes, 0x00, sizeof(pubkey1_decoded_bytes));

    cecies_hexstr2bin(keypair1.public_key.hexstring, sizeof(keypair1.public_key.hexstring) - 1, pubkey1_decoded_bytes, sizeof(pubkey1_decoded_bytes), &pubkey1_decoded_bytes_length);

    TEST_CHECK(56 == pubkey1_decoded_bytes_length);
    TEST_CHECK(0 == mbedtls_ecp_point_read_binary(&ecp_group1, &pubkey1, pubkey1_decoded_bytes, pubkey1_decoded_bytes_length));
    TEST_CHECK(0 == mbedtls_ecp_check_pubkey(&ecp_group1, &pubkey1));

    mbedtls_mpi_free(&prvkey1);
    mbedtls_ecp_point_free(&pubkey1);
    mbedtls_ecp_group_free(&ecp_group1);

    // Test without additional entropy.

    cecies_curve448_keypair keypair2;
    TEST_CHECK(0 == cecies_generate_curve448_keypair(&keypair2, NULL, 0));

    mbedtls_mpi prvkey2;
    mbedtls_mpi_init(&prvkey2);

    mbedtls_ecp_group ecp_group2;
    mbedtls_ecp_group_init(&ecp_group2);
    mbedtls_ecp_group_load(&ecp_group2, MBEDTLS_ECP_DP_CURVE448);

    mbedtls_ecp_point pubkey2;
    mbedtls_ecp_point_init(&pubkey2);

    size_t prvkey2_decoded_bytes_length;
    uint8_t prvkey2_decoded_bytes[256];

    cecies_hexstr2bin(keypair2.private_key.hexstring, sizeof(keypair2.private_key.hexstring) - 1, prvkey2_decoded_bytes, sizeof(prvkey2_decoded_bytes), &prvkey2_decoded_bytes_length);

    TEST_CHECK(0 == mbedtls_mpi_read_binary(&prvkey2, prvkey2_decoded_bytes, prvkey2_decoded_bytes_length));
    TEST_CHECK(0 == mbedtls_ecp_check_privkey(&ecp_group2, &prvkey2));

    size_t pubkey2_decoded_bytes_length;
    uint8_t pubkey2_decoded_bytes[113];
    cecies_hexstr2bin(keypair2.public_key.hexstring, sizeof(keypair2.public_key.hexstring) - 1, pubkey2_decoded_bytes, sizeof(pubkey2_decoded_bytes), &pubkey2_decoded_bytes_length);

    TEST_CHECK(56 == pubkey2_decoded_bytes_length);
    TEST_CHECK(0 == mbedtls_ecp_point_read_binary(&ecp_group2, &pubkey2, pubkey2_decoded_bytes, pubkey2_decoded_bytes_length));
    TEST_CHECK(0 == mbedtls_ecp_check_pubkey(&ecp_group2, &pubkey2));

    mbedtls_mpi_free(&prvkey2);
    mbedtls_ecp_point_free(&pubkey2);
    mbedtls_ecp_group_free(&ecp_group2);
}

static void cecies_generate_curve448_keypair_generated_keys_are_invalid()
{
    cecies_curve448_keypair keypair1;
    TEST_CHECK(0 == cecies_generate_curve448_keypair(&keypair1, (uint8_t*)"test test test", 14));

    mbedtls_mpi prvkey1;
    mbedtls_mpi_init(&prvkey1);

    mbedtls_ecp_group ecp_group1;
    mbedtls_ecp_group_init(&ecp_group1);
    mbedtls_ecp_group_load(&ecp_group1, MBEDTLS_ECP_DP_CURVE448);

    mbedtls_ecp_point pubkey1;
    mbedtls_ecp_point_init(&pubkey1);

    size_t prvkey1_decoded_bytes_length;
    uint8_t prvkey1_decoded_bytes[256];

    cecies_hexstr2bin(keypair1.private_key.hexstring, sizeof(keypair1.private_key.hexstring), prvkey1_decoded_bytes, sizeof(prvkey1_decoded_bytes), &prvkey1_decoded_bytes_length);
    prvkey1_decoded_bytes[0] = 0x9;
    prvkey1_decoded_bytes[1] = 13;

    mbedtls_mpi_read_binary(&prvkey1, prvkey1_decoded_bytes, prvkey1_decoded_bytes_length);

    TEST_CHECK(0 != mbedtls_ecp_check_privkey(&ecp_group1, &prvkey1));

    size_t pubkey1_decoded_bytes_length;
    uint8_t pubkey1_decoded_bytes[113];

    cecies_hexstr2bin(keypair1.public_key.hexstring, sizeof(keypair1.public_key.hexstring), pubkey1_decoded_bytes, sizeof(pubkey1_decoded_bytes), &pubkey1_decoded_bytes_length);
    pubkey1_decoded_bytes[0] = 1;
    TEST_CHECK(0 != mbedtls_ecp_point_read_binary(&ecp_group1, &pubkey1, pubkey1_decoded_bytes, 113));
    TEST_CHECK(0 != mbedtls_ecp_check_pubkey(&ecp_group1, &pubkey1));

    mbedtls_mpi_free(&prvkey1);
    mbedtls_ecp_point_free(&pubkey1);
    mbedtls_ecp_group_free(&ecp_group1);
}

static void cecies_generate_curve448_keypair_with_way_too_much_additional_entropy_successful_nonetheless()
{
    cecies_curve448_keypair keypair1;
    const char* additional_entropy = TEST_STRING;
    TEST_CHECK(0 == cecies_generate_curve448_keypair(&keypair1, (uint8_t*)additional_entropy, strlen(additional_entropy)));

    mbedtls_mpi prvkey1;
    mbedtls_mpi_init(&prvkey1);

    mbedtls_ecp_group ecp_group1;
    mbedtls_ecp_group_init(&ecp_group1);
    mbedtls_ecp_group_load(&ecp_group1, MBEDTLS_ECP_DP_CURVE448);

    mbedtls_ecp_point pubkey1;
    mbedtls_ecp_point_init(&pubkey1);

    size_t prvkey1_decoded_bytes_length;
    uint8_t prvkey1_decoded_bytes[256];

    cecies_hexstr2bin(keypair1.private_key.hexstring, sizeof(keypair1.private_key.hexstring), prvkey1_decoded_bytes, sizeof(prvkey1_decoded_bytes), &prvkey1_decoded_bytes_length);
    prvkey1_decoded_bytes[0] = 0x9;
    prvkey1_decoded_bytes[1] = 13;

    mbedtls_mpi_read_binary(&prvkey1, prvkey1_decoded_bytes, prvkey1_decoded_bytes_length);

    TEST_CHECK(0 != mbedtls_ecp_check_privkey(&ecp_group1, &prvkey1));

    size_t pubkey1_decoded_bytes_length;
    uint8_t pubkey1_decoded_bytes[113];

    cecies_hexstr2bin(keypair1.public_key.hexstring, sizeof(keypair1.public_key.hexstring), pubkey1_decoded_bytes, sizeof(pubkey1_decoded_bytes), &pubkey1_decoded_bytes_length);
    pubkey1_decoded_bytes[0] = 1;
    TEST_CHECK(0 != mbedtls_ecp_point_read_binary(&ecp_group1, &pubkey1, pubkey1_decoded_bytes, 113));
    TEST_CHECK(0 != mbedtls_ecp_check_pubkey(&ecp_group1, &pubkey1));

    mbedtls_mpi_free(&prvkey1);
    mbedtls_ecp_point_free(&pubkey1);
    mbedtls_ecp_group_free(&ecp_group1);
}

static void cecies_curve448_encrypt_raw_binary_decrypts_successfully()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 == cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(0 == memcmp(TEST_STRING, decrypted_string, sizeof(TEST_STRING)));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_base64_decrypts_successfully()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve448_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    TEST_CHECK(0 == cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(0 == memcmp(TEST_STRING, decrypted_string, sizeof(TEST_STRING)));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_bin_decrypt_with_public_key_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE448_PUBLIC_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static const cecies_curve448_key INVALID_CURVE448_KEY = { .hexstring = "Just something that isn't quite a key..." };

static void cecies_curve448_encrypt_bin_decrypt_with_invalid_key_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, INVALID_CURVE448_KEY, &decrypted_string, &decrypted_string_length));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static const cecies_curve448_key INVALID_CURVE448_KEY2 = { .hexstring = "Just something that isn't quite a key... At least this one has the same length as a key would be of this size ;D" };

static void cecies_curve448_encrypt_bin_decrypt_with_invalid_key_2_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, INVALID_CURVE448_KEY2, &decrypted_string, &decrypted_string_length));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static const cecies_curve448_key TEST_CURVE448_PUBLIC_KEY2 = { .hexstring = "1fe47d1a6954f51386764a9cfa1e54c06124a619d7fe5a20745842cb37dcb6ee1065769530230c8b91874f8256b583e7642d062cf6b06966" };

static const cecies_curve448_key TEST_CURVE448_PRIVATE_KEY2 = { .hexstring = "aa892c4e55f75d9cde14f6734bd1cea57c2c40c43fb56083f05211f8d616da57b6ea4ec92794806bac311d87c894528ad55d68322f6bc950" };

static void cecies_curve448_encrypt_bin_decrypt_with_wrong_key_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE448_PRIVATE_KEY2, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_bin_decrypt_with_zero_key_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    cecies_curve448_key z = { .hexstring = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" };
    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, z, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_bin_decrypt_with_NULL_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_NULL_ARG()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    encrypted_string = calloc(encrypted_string_length, sizeof(uint8_t));

    TEST_CHECK(CECIES_ENCRYPT_ERROR_CODE_NULL_ARG == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, NULL, 0));
    TEST_CHECK(CECIES_ENCRYPT_ERROR_CODE_NULL_ARG == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, NULL, &encrypted_string_length, 0));
    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    decrypted_string = calloc(encrypted_string_length, sizeof(uint8_t));

    TEST_CHECK(0 == cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(CECIES_DECRYPT_ERROR_CODE_NULL_ARG == cecies_curve448_decrypt(NULL, encrypted_string_length, 0, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(CECIES_DECRYPT_ERROR_CODE_NULL_ARG == cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE448_PRIVATE_KEY, NULL, &decrypted_string_length));
    TEST_CHECK(CECIES_DECRYPT_ERROR_CODE_NULL_ARG == cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, NULL));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_bin_decrypt_with_INVALID_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(CECIES_DECRYPT_ERROR_CODE_INVALID_ARG == cecies_curve448_decrypt(encrypted_string, 58, 0, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_base64_decrypt_invalid_base64_str_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve448_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    TEST_CHECK(0 == cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(CECIES_DECRYPT_ERROR_CODE_INVALID_ARG == cecies_curve448_decrypt((uint8_t*)"Definitively not a valid base64-encoded string! HJAB37GSVG37HJBSH83JBSH836TVSIV3663T7UV6TVSIV3663T7UVWGS87JBSH836TVSIV3663T7UV368736368", 135, 1, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_base64_decrypt_base64_with_or_without_NUL_terminator_both_succeeds()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));
    TEST_CHECK(encrypted_string_length == strlen((char*)encrypted_string));

    TEST_CHECK(encrypted_string[encrypted_string_length] == '\0');
    TEST_CHECK(0 == cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    free(decrypted_string);
    decrypted_string = NULL;
    TEST_CHECK(0 == cecies_curve448_decrypt(encrypted_string, encrypted_string_length + 1, 1, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_base64_decrypt_base64_lengths_identical()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));
    TEST_CHECK(encrypted_string_length == strlen((char*)encrypted_string));

    TEST_CHECK(0 == cecies_curve448_decrypt(encrypted_string, encrypted_string_length + 1, 1, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR == decrypted_string_length);

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_base64_decrypt_base64_compression_reduces_size()
{
    char test_string[4096 * 2];
    for (int i = 0; i < sizeof test_string; ++i)
    {
        test_string[i] = TEST_STRING[i % (TEST_STRING_LENGTH_WITHOUT_NUL_TERMINATOR)];
    }

    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)test_string, sizeof test_string, 9, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));
    TEST_CHECK(encrypted_string_length < sizeof test_string);

    TEST_CHECK(0 == cecies_curve448_decrypt(encrypted_string, encrypted_string_length + 1, 1, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));
    TEST_CHECK(sizeof test_string == decrypted_string_length);

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_null_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_NULL_ARG()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(CECIES_ENCRYPT_ERROR_CODE_NULL_ARG == cecies_curve448_encrypt(NULL, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, NULL, 0));
    TEST_CHECK(CECIES_ENCRYPT_ERROR_CODE_NULL_ARG == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, NULL, NULL, 0));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_invalid_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG == cecies_curve448_encrypt((uint8_t*)TEST_STRING, 0, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_base64_decrypt_base64_with_invalid_private_key_hex_format_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));
    TEST_CHECK(encrypted_string_length == strlen((char*)encrypted_string));

    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE448_PRIVATE_KEY_INVALID_HEX, &decrypted_string, &decrypted_string_length));

    //
}

static void cecies_curve448_encrypt_base64_decrypt_different_key_always_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve448_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    for (int i = 0; i < 64; ++i)
    {
        cecies_curve448_keypair kp;
        cecies_generate_curve448_keypair(&kp, (uint8_t*)"test test_*ç%°#@", 16);
        TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 1, kp.private_key, &decrypted_string, &decrypted_string_length));
    }

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_output_length_always_identical_with_calculated_prediction()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    encrypted_string_length = cecies_curve448_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR);

    //

    size_t written_bytes;
    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &written_bytes, 0));
    TEST_CHECK(written_bytes == encrypted_string_length);

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_base64_decrypt_base64_tampered_ephemeral_public_key_embedded_in_ciphertext_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve448_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    encrypted_string[64] = 'L';
    encrypted_string[65] = 'O';
    encrypted_string[66] = 'L';

    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_base64_decrypt_binary_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve448_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_binary_decrypt_base64_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_base64_decrypt_ciphertext_was_tampered_with_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    encrypted_string_length = cecies_calc_base64_length(cecies_curve448_calc_output_buffer_needed_size(TEST_STRING_LENGTH_WITH_NUL_TERMINATOR));

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1));

    encrypted_string[200] = 'A';
    encrypted_string[201] = 'B';
    encrypted_string[202] = 'C';
    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 1, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void cecies_curve448_encrypt_binary_decrypt_ciphertext_was_tampered_with_fails()
{
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length = 0;
    size_t decrypted_string_length = 0;

    //

    TEST_CHECK(0 == cecies_curve448_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH_WITH_NUL_TERMINATOR, 0, TEST_CURVE448_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 0));

    encrypted_string[200] = 'A';
    encrypted_string[201] = 'B';
    encrypted_string[202] = 'C';
    TEST_CHECK(0 != cecies_curve448_decrypt(encrypted_string, encrypted_string_length, 0, TEST_CURVE448_PRIVATE_KEY, &decrypted_string, &decrypted_string_length));

    //

    free(encrypted_string);
    free(decrypted_string);
}

// --------------------------------------------------------------------------------------------------------------

TEST_LIST = {
    //
    { "nulltest", null_test_success }, //
    // ------------------------------------------------------    Utils
    { "cecies_printvoid_returns_0", cecies_printvoid_returns_0 }, //
    { "cecies_fprintf_enables_and_disables_correctly", cecies_fprintf_enables_and_disables_correctly }, //
    { "cecies_hexstr2bin_invalid_args_returns_1", cecies_hexstr2bin_invalid_args_returns_1 }, //
    { "cecies_hexstr2bin_hexlen_odd_number_fails_returns_2", cecies_hexstr2bin_hexlen_odd_number_fails_returns_2 }, //
    { "cecies_hexstr2bin_insufficient_output_buffer_size_fails_returns_3", cecies_hexstr2bin_insufficient_output_buffer_size_fails_returns_3 }, //
    { "cecies_hexstr2bin_succeeds_both_with_and_without_nul_terminator", cecies_hexstr2bin_succeeds_both_with_and_without_nul_terminator }, //
    { "cecies_bin2hexstr_succeeds_output_length_double_the_input_length", cecies_bin2hexstr_succeeds_output_length_double_the_input_length }, //
    { "cecies_bin2hexstr_null_or_invalid_args_fails_returns_1", cecies_bin2hexstr_null_or_invalid_args_fails_returns_1 }, //
    { "cecies_bin2hexstr_insufficient_output_buffer_size_returns_2", cecies_bin2hexstr_insufficient_output_buffer_size_returns_2 }, //
    { "cecies_bin2hexstr_success_returns_0", cecies_bin2hexstr_success_returns_0 }, //
    // ------------------------------------------------------    Curve25519
    { "cecies_generate_curve25519_keypair_NULL_args_return_CECIES_KEYGEN_ERROR_CODE_NULL_ARG", cecies_generate_curve25519_keypair_NULL_args_return_CECIES_KEYGEN_ERROR_CODE_NULL_ARG }, //
    { "cecies_generate_curve25519_keypair_generated_keys_are_valid", cecies_generate_curve25519_keypair_generated_keys_are_valid }, //
    { "cecies_generate_curve25519_keypair_generated_keys_are_invalid", cecies_generate_curve25519_keypair_generated_keys_are_invalid }, //
    { "cecies_generate_curve25519_keypair_with_way_too_much_additional_entropy_successful_nonetheless", cecies_generate_curve25519_keypair_with_way_too_much_additional_entropy_successful_nonetheless }, //
    { "cecies_curve25519_encrypt_raw_binary_decrypts_successfully", cecies_curve25519_encrypt_raw_binary_decrypts_successfully }, //
    { "cecies_curve25519_encrypt_base64_decrypts_successfully", cecies_curve25519_encrypt_base64_decrypts_successfully }, //
    { "cecies_curve25519_encrypt_bin_decrypt_with_public_key_fails", cecies_curve25519_encrypt_bin_decrypt_with_public_key_fails }, //
    { "cecies_curve25519_encrypt_bin_decrypt_with_invalid_key_fails", cecies_curve25519_encrypt_bin_decrypt_with_invalid_key_fails }, //
    { "cecies_curve25519_encrypt_bin_decrypt_with_invalid_key_2_fails", cecies_curve25519_encrypt_bin_decrypt_with_invalid_key_2_fails }, //
    { "cecies_curve25519_encrypt_bin_decrypt_with_wrong_key_fails", cecies_curve25519_encrypt_bin_decrypt_with_wrong_key_fails }, //
    { "cecies_curve25519_encrypt_bin_decrypt_with_zero_key_fails", cecies_curve25519_encrypt_bin_decrypt_with_zero_key_fails }, //
    { "cecies_curve25519_encrypt_null_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_NULL_ARG", cecies_curve25519_encrypt_null_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_NULL_ARG }, //
    { "cecies_curve25519_encrypt_invalid_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG", cecies_curve25519_encrypt_invalid_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG }, //
    { "cecies_curve25519_encrypt_output_length_always_identical_with_calculated_prediction", cecies_curve25519_encrypt_output_length_always_identical_with_calculated_prediction }, //
    { "cecies_curve25519_encrypt_bin_decrypt_with_NULL_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_NULL_ARG", cecies_curve25519_encrypt_bin_decrypt_with_NULL_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_NULL_ARG }, //
    { "cecies_curve25519_encrypt_bin_decrypt_with_INVALID_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG", cecies_curve25519_encrypt_bin_decrypt_with_INVALID_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG }, //
    { "cecies_curve25519_encrypt_base64_decrypt_invalid_base64_str_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG", cecies_curve25519_encrypt_base64_decrypt_invalid_base64_str_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG }, //
    { "cecies_curve25519_encrypt_base64_decrypt_base64_with_or_without_NUL_terminator_both_succeeds", cecies_curve25519_encrypt_base64_decrypt_base64_with_or_without_NUL_terminator_both_succeeds }, //
    { "cecies_curve25519_encrypt_base64_decrypt_base64_with_invalid_private_key_hex_format_fails", cecies_curve25519_encrypt_base64_decrypt_base64_with_invalid_private_key_hex_format_fails }, //
    { "cecies_curve25519_encrypt_base64_decrypt_base64_tampered_ephemeral_public_key_embedded_in_ciphertext_fails", cecies_curve25519_encrypt_base64_decrypt_base64_tampered_ephemeral_public_key_embedded_in_ciphertext_fails }, //
    { "cecies_curve25519_encrypt_base64_decrypt_binary_fails", cecies_curve25519_encrypt_base64_decrypt_binary_fails }, //
    { "cecies_curve25519_encrypt_binary_decrypt_base64_fails", cecies_curve25519_encrypt_binary_decrypt_base64_fails }, //
    { "cecies_curve25519_encrypt_base64_decrypt_ciphertext_was_tampered_with_fails", cecies_curve25519_encrypt_base64_decrypt_ciphertext_was_tampered_with_fails }, //
    { "cecies_curve25519_encrypt_binary_decrypt_ciphertext_was_tampered_with_fails", cecies_curve25519_encrypt_binary_decrypt_ciphertext_was_tampered_with_fails }, //
    { "cecies_curve25519_encrypt_base64_decrypt_different_key_always_fails", cecies_curve25519_encrypt_base64_decrypt_different_key_always_fails }, //
    { "cecies_curve25519_encrypt_base64_decrypt_base64_lengths_identical", cecies_curve25519_encrypt_base64_decrypt_base64_lengths_identical }, //
    { "cecies_curve25519_encrypt_base64_decrypt_base64_compression_reduces_size", cecies_curve25519_encrypt_base64_decrypt_base64_compression_reduces_size }, //
    { "cecies_curve25519_encrypt_raw_binary_with_zlib_header_but_no_comprssion_still_decrypts_successfully", cecies_curve25519_encrypt_raw_binary_with_zlib_header_but_no_comprssion_still_decrypts_successfully }, //
    // ------------------------------------------------------    Curve448
    { "cecies_generate_curve448_keypair_NULL_args_return_CECIES_KEYGEN_ERROR_CODE_NULL_ARG", cecies_generate_curve448_keypair_NULL_args_return_CECIES_KEYGEN_ERROR_CODE_NULL_ARG }, //
    { "cecies_generate_curve448_keypair_generated_keys_are_valid", cecies_generate_curve448_keypair_generated_keys_are_valid }, //
    { "cecies_generate_curve448_keypair_generated_keys_are_invalid", cecies_generate_curve448_keypair_generated_keys_are_invalid }, //
    { "cecies_generate_curve448_keypair_with_way_too_much_additional_entropy_successful_nonetheless", cecies_generate_curve448_keypair_with_way_too_much_additional_entropy_successful_nonetheless }, //
    { "cecies_curve448_encrypt_raw_binary_decrypts_successfully", cecies_curve448_encrypt_raw_binary_decrypts_successfully }, //
    { "cecies_curve448_encrypt_base64_decrypts_successfully", cecies_curve448_encrypt_base64_decrypts_successfully }, //
    { "cecies_curve448_encrypt_bin_decrypt_with_public_key_fails", cecies_curve448_encrypt_bin_decrypt_with_public_key_fails }, //
    { "cecies_curve448_encrypt_bin_decrypt_with_invalid_key_fails", cecies_curve448_encrypt_bin_decrypt_with_invalid_key_fails }, //
    { "cecies_curve448_encrypt_bin_decrypt_with_invalid_key_2_fails", cecies_curve448_encrypt_bin_decrypt_with_invalid_key_2_fails }, //
    { "cecies_curve448_encrypt_bin_decrypt_with_wrong_key_fails", cecies_curve448_encrypt_bin_decrypt_with_wrong_key_fails }, //
    { "cecies_curve448_encrypt_bin_decrypt_with_zero_key_fails", cecies_curve448_encrypt_bin_decrypt_with_zero_key_fails }, //
    { "cecies_curve448_encrypt_null_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_NULL_ARG", cecies_curve448_encrypt_null_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_NULL_ARG }, //
    { "cecies_curve448_encrypt_invalid_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG", cecies_curve448_encrypt_invalid_args_fails_returns_CECIES_ENCRYPT_ERROR_CODE_INVALID_ARG }, //
    { "cecies_curve448_encrypt_output_length_always_identical_with_calculated_prediction", cecies_curve448_encrypt_output_length_always_identical_with_calculated_prediction }, //
    { "cecies_curve448_encrypt_bin_decrypt_with_NULL_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_NULL_ARG", cecies_curve448_encrypt_bin_decrypt_with_NULL_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_NULL_ARG }, //
    { "cecies_curve448_encrypt_bin_decrypt_with_INVALID_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG", cecies_curve448_encrypt_bin_decrypt_with_INVALID_args_fails_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG }, //
    { "cecies_curve448_encrypt_base64_decrypt_invalid_base64_str_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG", cecies_curve448_encrypt_base64_decrypt_invalid_base64_str_returns_CECIES_DECRYPT_ERROR_CODE_INVALID_ARG }, //
    { "cecies_curve448_encrypt_base64_decrypt_base64_with_or_without_NUL_terminator_both_succeeds", cecies_curve448_encrypt_base64_decrypt_base64_with_or_without_NUL_terminator_both_succeeds }, //
    { "cecies_curve448_encrypt_base64_decrypt_base64_with_invalid_private_key_hex_format_fails", cecies_curve448_encrypt_base64_decrypt_base64_with_invalid_private_key_hex_format_fails }, //
    { "cecies_curve448_encrypt_base64_decrypt_base64_tampered_ephemeral_public_key_embedded_in_ciphertext_fails", cecies_curve448_encrypt_base64_decrypt_base64_tampered_ephemeral_public_key_embedded_in_ciphertext_fails }, //
    { "cecies_curve448_encrypt_base64_decrypt_binary_fails", cecies_curve448_encrypt_base64_decrypt_binary_fails }, //
    { "cecies_curve448_encrypt_binary_decrypt_base64_fails", cecies_curve448_encrypt_binary_decrypt_base64_fails }, //
    { "cecies_curve448_encrypt_base64_decrypt_ciphertext_was_tampered_with_fails", cecies_curve448_encrypt_base64_decrypt_ciphertext_was_tampered_with_fails }, //
    { "cecies_curve448_encrypt_binary_decrypt_ciphertext_was_tampered_with_fails", cecies_curve448_encrypt_binary_decrypt_ciphertext_was_tampered_with_fails }, //
    { "cecies_curve448_encrypt_base64_decrypt_different_key_always_fails", cecies_curve448_encrypt_base64_decrypt_different_key_always_fails }, //
    { "cecies_curve448_encrypt_base64_decrypt_base64_lengths_identical", cecies_curve448_encrypt_base64_decrypt_base64_lengths_identical }, //
    { "cecies_curve448_encrypt_base64_decrypt_base64_compression_reduces_size", cecies_curve448_encrypt_base64_decrypt_base64_compression_reduces_size }, //
    //
    // ----------------------------------------------------------------------------------------------------------
    //
    { NULL, NULL } //
};
