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

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#include <objbase.h>
#else
#include <sys/param.h>
#ifdef __FreeBSD__
#include <uuid.h>
#else
#include <uuid/uuid.h>
#endif
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cecies/guid.h"

#define CECIES_GUID_LOWERCASE_HYPHENS "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define CECIES_GUID_LOWERCASE_NO_HYPHENS "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x"
#define CECIES_GUID_UPPERCASE_HYPHENS "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X"
#define CECIES_GUID_UPPERCASE_NO_HYPHENS "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X"
#define CECIES_GET_GUID_FORMAT(lowercase, hyphens) ((lowercase) ? (hyphens) ? (CECIES_GUID_LOWERCASE_HYPHENS) : (CECIES_GUID_LOWERCASE_NO_HYPHENS) : (hyphens) ? (CECIES_GUID_UPPERCASE_HYPHENS) : (CECIES_GUID_UPPERCASE_NO_HYPHENS))

static const cecies_guid CECIES_EMPTY_GUID = { .string = "00000000-0000-0000-0000-000000000000" };

cecies_guid cecies_empty_guid()
{
    return CECIES_EMPTY_GUID;
}

#ifdef _WIN32

cecies_guid cecies_new_guid(const int lowercase, const int hyphens)
{
    cecies_guid out;
    memset(&out, 0x00, sizeof(out));

    GUID guid = { 0 };
    if (CoCreateGuid(&guid) == S_OK)
    {
        snprintf(out.string, sizeof(out.string), CECIES_GET_GUID_FORMAT(lowercase, hyphens), guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    }

    return out;
}

#elif defined(__FreeBSD__)

cecies_guid cecies_new_guid(const int lowercase, const int hyphens)
{
    cecies_guid out;
    memset(out.string, '\0', sizeof(out.string));

    uint32_t status;
    uuid_t uuid;
    uuid_create(&uuid, &status);

    char* tmp = NULL;
    uuid_to_string(&uuid, &tmp, &status);
    const size_t tmplen = strlen(tmp);

    if (!lowercase)
    {
        for (int i = 0; i < tmplen; ++i)
        {
            tmp[i] = toupper(tmp[i]);
        }
    }

    if (hyphens)
    {
        memcpy(out.string, tmp, tmplen);
    }
    else
    {
        char* c = out.string;
        for (int i = 0; i < sizeof(tmp); ++i)
        {
            if (tmp[i] != '-')
            {
                *(c++) = tmp[i];
            }
        }
    }

    free(tmp);
    return out;
}

#else

cecies_guid cecies_new_guid(const int lowercase, const int hyphens)
{
    cecies_guid out;
    memset(&out, 0x00, sizeof(out));

    uuid_t uuid;
    uuid_generate(uuid);

    char tmp[sizeof(out.string)];
    if (lowercase)
    {
        uuid_unparse_lower(uuid, tmp);
    }
    else
    {
        uuid_unparse_upper(uuid, tmp);
    }

    if (hyphens)
    {
        memcpy(out.string, tmp, sizeof(tmp));
    }
    else
    {
        char* c = out.string;
        for (int i = 0; i < sizeof(tmp); ++i)
        {
            if (tmp[i] != '-')
            {
                *(c++) = tmp[i];
            }
        }
    }

    return out;
}

#endif

#undef CECIES_GUID_LOWERCASE_HYPHENS
#undef CECIES_GUID_LOWERCASE_NO_HYPHENS
#undef CECIES_GUID_UPPERCASE_HYPHENS
#undef CECIES_GUID_UPPERCASE_NO_HYPHENS
#undef CECIES_GET_GUID_FORMAT

#ifdef __cplusplus
} // extern "C"
#endif