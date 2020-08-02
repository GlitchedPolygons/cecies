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
#include <sha512.h>
#include <ed25519.h>
#include <cecies/util.h>

int main(int argc, const char* argv[])
{
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        fprintf(stdout, "ed25519_verify:  Verify an Ed25519 signature using a specific public key. Call this program using exactly 3 arguments;  the FIRST one being the PUBLIC KEY (hex-string), the SECOND one being the SIGNATURE to verify (also a hex-string) and the THIRD one the actual STRING TO VERIFY the signature against.\n");
        return 0;
    }

    if (argc != 4)
    {
        fprintf(stderr, "ed25519_verify: wrong argument count. Check out \"ed25519_verify --help\" for more details about how to use this!\n");
        return -1;
    }

    int r = -1;

    // TODO: impl. asap!

exit:
    return r;
}
