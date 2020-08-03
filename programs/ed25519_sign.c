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
        fprintf(stdout, "ed25519_sign: Sign a string using Ed25519 (the underlying hash function is SHA2-512). This program takes exactly 2 arguments: the first one being the private key with which to sign (hex-string), and the second one the message string that you want to sign.\n");
        return 0;
    }

    if (argc != 3)
    {
        fprintf(stderr, "ed25519_sign: Failed! Wrong argument count... Check out \"ed25519_sign --help\" for more details about how to use this!\n");
        return 1;
    }

    char* msg = argv[2];
    size_t msg_len = strlen(msg);

    if (msg_len == 0)
    {
        fprintf(stderr, "ed25519_sign: Failed! Message to sign is empty...\n");
        return 2;
    }

    int r = -1;

    unsigned char signature[64];
    unsigned char private_key[64 + 1];
    char* private_key_hexstr = argv[1];
    size_t private_key_hexstr_len = strlen(private_key_hexstr);

    if (private_key_hexstr_len != 128)
    {
        fprintf(stderr, "ed25519_sign: Invalid private key format/length!\n");
        r = 3;
        goto exit;
    }

    if (cecies_hexstr2bin(private_key_hexstr, private_key_hexstr_len, private_key, sizeof(private_key), NULL) != 0)
    {
        fprintf(stderr, "ed25519_sign: Invalid private key format/length!\n");
        r = 3;
        goto exit;
    }

    if (crypto_sign_ed25519_detached(signature, NULL, (const unsigned char*)msg, msg_len, private_key) != 0)
    {
        fprintf(stderr, "ed25519_sign: The generated signature is invalid!\n");
        r = 4;
        goto exit;
    }

    for (int i = 0; i < sizeof(signature); ++i)
    {
        fprintf(stdout, "%02x", signature[i]);
    }

    fprintf(stdout, "\n");

    r = 0;

exit:
    memset(msg, 0x00, msg_len);
    memset(signature, 0x00, sizeof(signature));
    memset(private_key, 0x00, sizeof(private_key));
    memset(private_key_hexstr, 0x00, private_key_hexstr_len);

    msg_len = private_key_hexstr_len = 0;

    return r;
}
