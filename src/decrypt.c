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
#include <stdbool.h>
#include "cecies/decrypt.h"

int cecies_decrypt(const unsigned char* encrypted_data, const size_t encrypted_data_length, const unsigned char* private_key, const size_t private_key_length, const bool private_key_base64, unsigned char* output, const size_t output_bufsize, size_t* output_length)
{
    if (encrypted_data == NULL //
            || private_key == NULL //
            || output == NULL //
            || output_length == NULL)
    {
        fprintf(stderr, "CECIES decryption failed: one or more NULL arguments.");
        return CECIES_DECRYPT_ERROR_CODE_NULL_ARG;
    }

    if (encrypted_data_length == 0 //
            || private_key_length == 0 //
            || output_bufsize == 0)
    {
        fprintf(stderr, "CECIES decryption failed: one or more invalid arguments.");
        return CECIES_DECRYPT_ERROR_CODE_INVALID_ARG;
    }

    if (output_bufsize < encrypted_data_length)
    {
        fprintf(stderr, "CECIES decryption failed due to insufficient output buffer size. Please allocate at least as many bytes as the encrypted input buffer to be sure.");
        return CECIES_DECRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
    }

    int ret = 1;

    // TODO: implement ASAP
}