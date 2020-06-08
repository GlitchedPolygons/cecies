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
 */

int main(void)
{
    printf("\n---- CECIES ----\n-- Example 02 --\n\n");

    unsigned char public_key[256];
    memset(public_key, 0x00, sizeof(public_key));

    unsigned char private_key[256];
    memset(private_key, 0x00, sizeof(private_key));

    size_t public_key_length;
    size_t private_key_length;

    int r = cecies_generate_curve448_keypair(true, private_key, sizeof(private_key), &private_key_length, public_key, sizeof(public_key), &public_key_length, NULL, 0);

    if (r != 0)
    {
        printf("CECIES example key-pair generation failed!  cecies_generate_curve448_keypair returned %d", r);
        return r;
    }

    printf("Successfully generated CECIES key-pair (Curve448)\n\nPrivate key: %s\n\nPublic key: %s\n\n", private_key, public_key);

    return r;
}