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
#include <stdint.h>
#include <string.h>
#include <cecies/keygen.h>

/*
 *     This example shows how to generate CECIES keypairs.
 *     The results are written into a cecies_curve448_keypair struct instance
 *     and are basically the private key, which is a bignum (known in MbedTLS as an mbedtls_mpi)
 *     written as a binary array (BIG endian)
 */

int main(void)
{
    printf("\n---- CECIES ----\n-- Example 02 --\n\n");

    cecies_curve448_keypair keypair;

    int r = cecies_generate_curve448_keypair(&keypair, NULL, 0);

    if (r != 0)
    {
        printf("CECIES example key-pair generation failed!  cecies_generate_curve448_keypair returned %d", r);
        return r;
    }

    printf("Successfully generated CECIES key-pair (Curve448)\n\nPrivate key: %s\n\nPublic key: %s\n\n", keypair.private_key, keypair.public_key);

    memset(&keypair, 0x00, sizeof(keypair));
    return r;
}