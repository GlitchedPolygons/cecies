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

/**
 *  @file guid.h
 *  @author Raphael Beck
 *  @brief Mh! The smell of fresh GUIDs..
 */

#ifndef CECIES_GUID_H
#define CECIES_GUID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"

/**
 * Gets an empty GUID (<c>"00000000-0000-0000-0000-000000000000"</c>).
 * @return <c>"00000000-0000-0000-0000-000000000000"</c>
 */
CECIES_API cecies_guid cecies_empty_guid();

/**
 * Generates a new GUID (a.k.a. UUID).
 * @param lowercase Should the GUID be lowercase or UPPERCASE only? Pass \c 0 for \c false, anything else for \c true.
 * @param hyphens Should the GUID contain hyphen separators? Pass \c 0 for \c false, anything else for \c true.
 * @return The cecies_guid
 */
CECIES_API cecies_guid cecies_new_guid(int lowercase, int hyphens);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_GUID_H
