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
#include <string.h>
#include <cecies/util.h>
#include <sodium.h>

int main(int argc, char* argv[])
{
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        fprintf(stdout, "ed25519_verify:  Verify an Ed25519 signature using a specific public key. Call this program using exactly 3 arguments;  the FIRST one being the PUBLIC KEY (hex-string), the SECOND one being the SIGNATURE to verify (also a hex-string) and the THIRD one the actual STRING TO VERIFY the signature against.\n");
        return 0;
    }

    if (argc != 4)
    {
        fprintf(stderr, "ed25519_verify: wrong argument count. Check out \"ed25519_verify --help\" for more details about how to use this!\n");
        return 1;
    }

    char* msg = argv[3];
    size_t msg_len = strlen(msg);

    if (msg_len == 0)
    {
        fprintf(stderr, "ed25519_verify: Failed! Message to verify is empty...\n");
        return 2;
    }

    int r = -1;
    unsigned char signature[64 + 1];
    unsigned char public_key[32 + 1];

    char* public_key_hexstr = argv[1];
    size_t public_key_hexstr_len = strlen(public_key_hexstr);

    char* signature_hexstr = argv[2];
    size_t signature_hexstr_len = strlen(signature_hexstr);

    if (public_key_hexstr_len != 64)
    {
        fprintf(stderr, "ed25519_verify: Invalid public key format/length!\n");
        r = 3;
        goto exit;
    }

    if (cecies_hexstr2bin(public_key_hexstr, public_key_hexstr_len, public_key, sizeof(public_key), NULL) != 0)
    {
        fprintf(stderr, "ed25519_verify: Invalid public key format/length!\n");
        r = 3;
        goto exit;
    }

    if (signature_hexstr_len != 128)
    {
        fprintf(stderr, "ed25519_verify: Invalid signature!\n");
        r = 4;
        goto exit;
    }

    if (cecies_hexstr2bin(signature_hexstr, signature_hexstr_len, signature, sizeof(signature), NULL) != 0)
    {
        fprintf(stderr, "ed25519_verify: Invalid signature!\n");
        r = 4;
        goto exit;
    }

    if (crypto_sign_ed25519_verify_detached(signature, (const unsigned char*)msg, msg_len, public_key) != 0)
    {
        fprintf(stderr, "ed25519_verify: Invalid signature!\n");
        r = 4;
        goto exit;
    }

    r = 0;
    fprintf(stderr, "ed25519_verify: Signature valid!\n");

exit:
    memset(msg, 0x00, msg_len);

    memset(signature, 0x00, sizeof(signature));
    memset(signature_hexstr, 0x00, signature_hexstr_len);

    memset(public_key, 0x00, sizeof(public_key));
    memset(public_key_hexstr, 0x00, public_key_hexstr_len);

    msg_len = public_key_hexstr_len = signature_hexstr_len = 0;

    return r;
}
