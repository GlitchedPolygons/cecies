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
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>
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
    unsigned char a1[512];
    unsigned char a2[512];
    unsigned char a3[512];
    unsigned char a4[512];

    assert_int_equal(CECIES_KEYGEN_ERROR_CODE_NULL_ARG, cecies_generate_curve448_keypair(true,NULL,512,))
    //
}

// --------------------------------------------------------------------------------------------------------------

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
