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
#include <mbedtls/platform_util.h>

/*
 *     This example shows how to generate CECIES keypairs.
 *     The results are written into a cecies_curve448_keypair struct instance
 *     and are basically the private key, which is a bignum (known in MbedTLS as an mbedtls_mpi)
 *     written as a binary array (BIG endian) and exported as hex string into cecies_curve448_keypair.private_key
 *     and the public key, which is a point on the curve (mbedtls_ecp_point) and also exported into cecies_curve448_keypair.public_key as a hex string.
 */

int main(int argc, char* argv[])
{
    cecies_enable_fprintf(); // Allow fprintf in case errors occur and need to be fprintf'ed.
    printf("\n---- CECIES ----\n-- Example 02 --\n\n");

    const char* additional_entropy = argc > 1 ? argv[1] : NULL;
    const size_t additional_entropy_length = additional_entropy ? strlen(additional_entropy) : 0;

    if (additional_entropy != NULL)
    {
        printf("Using additional entropy string \"%s\"\n", additional_entropy);
    }

    cecies_curve448_keypair keypair;

    int r = cecies_generate_curve448_keypair(&keypair, (unsigned char*)additional_entropy, additional_entropy_length);

    if (r != 0)
    {
        printf("\nCECIES example key-pair generation failed!  cecies_generate_curve448_keypair returned %d\n", r);
        return r;
    }

    printf("\nSuccessfully generated CECIES key-pair (Curve448)\n\nPrivate key:  %s\n\nPublic key:   %s\n\n", keypair.private_key.hexstring, keypair.public_key.hexstring);

    mbedtls_platform_zeroize(&keypair, sizeof(keypair));
    cecies_disable_fprintf();
    return r;
}