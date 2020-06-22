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
#include <cecies/keygen.h>

int main(int argc, const char* argv[])
{
    cecies_curve448_keypair keypair;

    unsigned char additional_entropy[128];
    size_t rem = sizeof(additional_entropy);

    for (int i = 1; i < argc && rem > 0; i++)
    {
        const char* istr = argv[i];
        const size_t ilen = CECIES_MIN(rem, strlen(istr));
        snprintf((char*)(additional_entropy + (128 - rem)), ilen, "%s", istr);
        rem -= ilen;
    }

    const int r = cecies_generate_curve448_keypair(&keypair, additional_entropy, sizeof additional_entropy);
    if (r != 0)
    {
        return r;
    }

    fprintf(stdout, "{\"curve448_private_key\":\"%s\",\"curve448_public_key\":\"%s\"}", keypair.private_key.hexstring, keypair.public_key.hexstring);

    // Cleanup:
    memset(&keypair, 0x00, sizeof(cecies_curve448_keypair));
    memset(additional_entropy, 0x00, sizeof(additional_entropy));
    return 0;
}
