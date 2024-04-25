
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
#include <cecies/util.h>
#include <cecies/encrypt.h>
#include <cecies/decrypt.h>

/*
 *     This is the example test string to encrypt and decrypt.
 */
static const char TEST_STRING[] = "Doctor Freeman. I realize this moment may not be the most convenient for a heart-to-heart, but I had to wait until your friends were otherwise occupied. Hm. There was a time they cared nothing for Miss Vance... When their only experience of humanity was a crowbar coming at them down a steel corridor.";

   static const cecies_SECP256K1_pub_key TEST_PUBLIC_KEY = { .hexstring = "049ff6a73c7ac3ef7972ee0ac53223c91b1f1bc461fd503565ae455c1b9f1d50c70c02891fdbd3cdd995831a53f9d6f14f4bf866d1f6cb62b08506660e537a5c8e" };
   static const cecies_SECP256K1_priv_key TEST_PRIVATE_KEY = { .hexstring = "142743f6471061101916ed63896254a2bd078b12c56bd4acdbebfe4ce1472aa1" };

   int main(void)
   {
       int s = 1;

       // sizeof(TEST_STRING) instead of strlen(TEST_STRING) because we also want to encrypt the NUL-terminator character along. Never forget the NUL-terminator in C-strings!
       const size_t TEST_STRING_LENGTH = sizeof(TEST_STRING);

       printf("\n---- CECIES ----\n-- Example 05 --\n\n");
       printf("Encrypting the following string:\n\n%s\n\n", TEST_STRING);

       uint8_t* encrypted_string;
       size_t encrypted_string_length;

       s = cecies_secp256k1_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH, 0, TEST_PUBLIC_KEY, &encrypted_string, &encrypted_string_length, 1);

       if (s != 0)
       {
           printf("Encryption failed! \"cecies_SECP256K1_encrypt\" returned: %d\n", s);
           return s;
       }

       printf("Encrypted string >>> base64:\n\n%s\n\nStatus code: %d\n\n", encrypted_string, s);

       size_t decrypted_string_length;
       char* decrypted_string;

       s = cecies_secp256k1_decrypt(encrypted_string, encrypted_string_length, 1, TEST_PRIVATE_KEY, (uint8_t**)&decrypted_string, &decrypted_string_length);

       printf("Decrypted string:\n\n%s\n\nStatus code: %d\n\n", decrypted_string, s);

       cecies_free(encrypted_string);
       cecies_free(decrypted_string);

       return s;
   }