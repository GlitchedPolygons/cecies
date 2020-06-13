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

#include "cecies/util.h"

int cecies_hexstr2bin(const char* hexstr, const size_t hexstr_length, unsigned char* output, const size_t output_size, size_t* output_length)
{
    if (hexstr == NULL || output == NULL || hexstr_length == 0)
    {
        return 1;
    }

    const size_t hl = hexstr[hexstr_length - 1] ? hexstr_length : hexstr_length - 1;

    if (hl % 2 != 0)
    {
        return 2;
    }

    const size_t final_length = hl / 2;

    if (output_size < final_length + 1)
    {
        return 3;
    }

    for (size_t i = 0, ii = 0; ii < final_length; i += 2, ii++)
    {
        output[ii] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
    }

    output[final_length] = '\0';

    if (output_length != NULL)
    {
        *output_length = final_length;
    }

    return 0;
}

int cecies_bin2hexstr(const unsigned char* bin, const size_t bin_length, char* output, const size_t output_size, size_t* output_length, const bool uppercase)
{
    if (bin == NULL || bin_length == 0 || output == NULL)
    {
        return 1;
    }

    const size_t final_length = bin_length * 2;

    if (output_size < final_length + 1)
    {
        return 2;
    }

    const char* format = uppercase ? "%02X" : "%02x";

    for (size_t i = 0; i < bin_length; i++)
    {
        sprintf(output + i * 2, format, bin[i]);
    }

    output[final_length] = '\0';

    if (output_length != NULL)
    {
        *output_length = final_length;
    }

    return 0;
}

static bool _cecies_fprintf_enabled = true;

bool cecies_is_fprintf_enabled()
{
    return _cecies_fprintf_enabled;
}

void cecies_enable_fprintf()
{
    _cecies_fprintf_enabled = true;
}

void cecies_disable_fprintf()
{
    _cecies_fprintf_enabled = false;
}

int cecies_fprintf(FILE* stream, const char* format, ...)
{
    if (cecies_is_fprintf_enabled())
    {
        va_list arglist;
        va_start(arglist, format);
        const int r = vfprintf(stream, format, arglist);
        va_end(arglist);
        return r;
    }

    return 0;
}
