SET ret=%CD%
SET repo=%~dp0
SET out="%repo%\build-msvc"
if exist %out% ( rd /s /q %out% )
mkdir %out% && cd %out%
cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DCECIES_ENABLE_TESTS=Off -DCECIES_ENABLE_PROGRAMS=On -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
mkdir include
xcopy ..\include .\include
mkdir dll && cd dll
cmake -DBUILD_SHARED_LIBS=On -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DCECIES_BUILD_DLL=On -DCECIES_ENABLE_PROGRAMS=Off -DCECIES_ENABLE_TESTS=Off -DCMAKE_BUILD_TYPE=Release ..\..
cmake --build . --config Release
cd ..
tar -czvf cecies.tar.gz Release\* programs\Release\*.exe dll\Release\*.dll dll\Release\*.lib dll\Release\*.exp
cd %RET%