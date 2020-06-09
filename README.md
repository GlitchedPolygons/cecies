# CECIES
## ECIES implementation in C using MbedTLS

This is a super easy and straightforward C implementation of the Elliptic Curve Integrated Encryption Scheme as defined in [SECG SEC-1 **(Section 5.1)**](http://www.secg.org/sec1-v2.pdf), [ISO/IEC 18033-2](https://www.shoup.net/iso/std4.pdf), [ANSI X9.63](ftp://ftp.iks-jena.de/mitarb/lutz/standards/ansi/X9/x963-7-5-98.pdf), etc...
More useful information also accessible [here](https://asecuritysite.com/encryption/ecc3), [here](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption) aand [here](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme).

---

### How to clone
`git clone --recursive https://github.com/GlitchedPolygons/cecies.git`

### How to use
Just add CECIES as a git submodule to your project (e.g. into some `lib/` or `deps/` folder inside your project's repo; `{repo_root}/lib/` is used here in the following example).

```
git submodule add https://github.com/GlitchedPolygons/cecies.git lib/
git submodule update --init --recursive
```

If you don't want to use git submodules, you can also start vendoring a specific version of CECIES by copying its full repo content into the folder where you keep your project's external libraries/dependencies.

**Never expose your private keys, take extra care when handling them and always clean up after doing crypto ops in C (don't leave private key buffers lying around in RAM at any point when they are not needed!).**

### Linking

If you use [CMake](https://cmake.org) you can just `add_subdirectory(path_to_submodule)` and then `target_link_libraries(your_project PRIVATE cecies)` inside your CMakeLists.txt file.

### Examples

To find out how to use the encrypt and decrypt functions, [check out the docs](https://glitchedpolygons.github.io/cecies/files.html) or [the provided example .c files.](https://github.com/GlitchedPolygons/cecies/tree/master/examples).
