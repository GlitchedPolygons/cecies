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

#ifndef CECIES_VERIFY_H
#define CECIES_VERIFY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#define CECIES_VERIFY_ERROR_CODE_NULL_ARG 4000
#define CECIES_VERIFY_ERROR_CODE_INVALID_ARG 4001
#define CECIES_VERIFY_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE 4002
#define CECIES_VERIFY_ERROR_CODE_OUT_OF_MEMORY 4003

// TODO: declare ECDSA verification functions here

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CECIES_VERIFY_H
