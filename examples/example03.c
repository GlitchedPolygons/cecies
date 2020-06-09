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
#include <cecies/sign.h>

/*
 *     This example shows how to sign data using ECDSA with Curve448.
 */

static const char TEST_STRING[] = "Lorem ipsum dolor sick fuck amend something something ...";

static const char TEST_PUBLIC_KEY[] = "BMAocEd2hsZvNRynFSu8YeCfOu2wkXMALnDkr2hALy5cfiECpi2b21j9lXpoijwBkULMy234iR69AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

static const char TEST_PRIVATE_KEY[] = "8FNsJbVMlSwr41fb8ktgWjG8WyyAup1j0icaspuiTtCxt7C//m84283s/VK8NDvstvxho2PR5qA=";

int main(void)
{
    printf("\n---- CECIES ----\n-- Example 03 --\n\n");

    cecies_sign(TEST_STRING, sizeof(TEST_STRING),TEST_PRIVATE_KEY,strlen(TEST_PRIVATE_KEY),true,signature, sizeof(signature),)

    return r;
}