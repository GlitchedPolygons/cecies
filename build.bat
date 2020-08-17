SET repo=%~dp0
SET out="%repo%\build-msvc"
if exist %out% ( rd /s /q %out% )
mkdir %out% && cd %out%
cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DCECIES_ENABLE_TESTS=Off -DCECIES_ENABLE_PROGRAMS=On -DCMAKE_BUILD_TYPE=Release ..
msbuild cecies.vcxproj /p:configuration=release
msbuild programs\ALL_BUILD.vcxproj /p:configuration=release
mkdir include
xcopy ..\include .\include
tar -czvf cecies.tar.gz Release\* programs\Release\*.exe
cd ..