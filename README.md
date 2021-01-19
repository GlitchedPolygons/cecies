# CECIES
## ECIES implementation in C using MbedTLS

[![Codacy](https://app.codacy.com/project/badge/Grade/4f7b604713ff43f788758013a460b2c5)](https://www.codacy.com/manual/GlitchedPolygons/cecies?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=GlitchedPolygons/cecies&amp;utm_campaign=Badge_Grade)
[![Codecov](https://codecov.io/gh/GlitchedPolygons/cecies/branch/master/graph/badge.svg)](https://codecov.io/gh/GlitchedPolygons/cecies)
[![CircleCI](https://circleci.com/gh/GlitchedPolygons/cecies/tree/master.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/cecies/tree/master)
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-orange)](https://github.com/GlitchedPolygons/cecies/blob/master/LICENSE)
[![API Docs](https://img.shields.io/badge/api-docs-informational.svg)](https://glitchedpolygons.github.io/cecies/files.html)

This is a super easy and straightforward C implementation of the Elliptic Curve Integrated Encryption Scheme as defined in [SECG SEC-1 **(Section 5.1)**](http://www.secg.org/sec1-v2.pdf), [ISO/IEC 18033-2](https://www.shoup.net/iso/std4.pdf), [ANSI X9.63](ftp://ftp.iks-jena.de/mitarb/lutz/standards/ansi/X9/x963-7-5-98.pdf), etc...

More useful information also accessible [here](https://asecuritysite.com/encryption/ecc3), [here](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption) aand [here](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme).

---

### How to clone

`git clone --recursive https://github.com/GlitchedPolygons/cecies.git`

### How to use

Just add CECIES as a git submodule to your project (e.g. into some `lib/` or `deps/` folder inside your project's repo; `{repo_root}/lib/` is used here in the following example).

```
git submodule add https://github.com/GlitchedPolygons/cecies.git lib/cecies
git submodule update --init --recursive
```

If you don't want to use git submodules, you can also start vendoring a specific version of CECIES by copying its full repo content into the folder where you keep your project's external libraries/dependencies.

**Never expose your private keys, take extra care when handling them and always clean up after doing crypto ops in C (don't leave private key buffers lying around in RAM at any point when they are not needed!).**

### Compiling

There are pre-built binaries for every major platform for you to download inside the [GitHub Releases page](https://github.com/GlitchedPolygons/cecies/releases). Thanks for downloading, and I hope you enjoy!

Oh, you're still here :) You really want to compile it yourself, huh. 
Cool. 

Look, just execute the following command and you'll have your CECIES comfortably built and packaged for you automatically into a _.tar.gz_ file that you will find inside the `build/` folder.

```bash
bash build.sh
```
This works on Windows too: just use the [Git Bash for Windows](https://git-scm.com/download/win) CLI!

#### MinGW on Windows

```bash
bash build-mingw.sh
```
Wanna compile using [MinGW-w64](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Personal%20Builds/mingw-builds/installer/mingw-w64-install.exe)? Run this using e.g. "Git Bash for Windows". Make sure that you have your MinGW installation directory inside your `PATH` - otherwise this script will fail when trying to call `mingw32-make.exe`.

Official release builds are made using `mingw-w64/x86_64-8.1.0-posix-seh-rt_v6-rev0/mingw64/bin/gcc.exe`.

### Linking

#### CMake

If you use [CMake](https://cmake.org) you can just `add_subdirectory(path_to_submodule)` and then `target_link_libraries(your_project PRIVATE cecies)` inside your CMakeLists.txt file. Done! You can now include CECIES headers in your code and be done with it.
This is equivalent to static linking by default, but much more pleasant than the manual variant.

#### Dynamic linking

* To dynamically link CECIES into your application on Windows, you need to `#define CECIES_DLL` before including any of the CECIES headers in your code! (Or, alternatively, add the `CECIES_DLL` pre-processor definition inside your build script/solution config)
* * This will add the `__declspec(dllexport)` declaration that is needed on Windows to the various CECIES functions.
* If you did not grab the pre-built DLL, you need to define/pass the pre-processor macro `CECIES_BUILD_DLL` before compiling CECIES!
* * Your consuming code should then only `#define CECIES_DLL` (as stated above).
* For shared libs: always have the CECIES shared library reachable inside your `$PATH`, or copy it into the same directory where your application's executable resides.

**Note:** the default configuration for building CECIES as a shared library compiles the MbedTLS dependency targets as [position-independent code](https://en.wikipedia.org/wiki/Position-independent_code) directly into the CECIES shared library, so that you only need to include one `cecies.dll` file (or `.so`/`.dylib` file, whatever) with your application.

If this is not what you want, you are free to manually compile [MbedTLS](https://github.com/ARMmbed/mbedtls) as a DLL too and modify the [CMakeLists.txt](https://github.com/GlitchedPolygons/cecies/blob/master/CMakeLists.txt) file accordingly.

#### Static linking

Linking statically feels best when done directly via CMake's `add_subdirectory(path_to_submodule)` command as seen above, but if you still want to build CECIES as a static lib
yourself and link statically against it, you need to remember to also link your consuming application against `mbedx509`, `mbedtls` and `mbedcrypto` besides `cecies`!

### Examples

To find out how to use the encrypt and decrypt functions, [check out the docs](https://glitchedpolygons.github.io/cecies/files.html) or [the provided example .c files.](https://github.com/GlitchedPolygons/cecies/tree/master/examples).

# _In Curve448 we trust!_
