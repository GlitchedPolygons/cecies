::  Copyright 2020 Raphael Beck
::
::  Licensed under the Apache License, Version 2.0 (the "License");
::  you may not use this file except in compliance with the License.
::  You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
::  Unless required by applicable law or agreed to in writing, software
::  distributed under the License is distributed on an "AS IS" BASIS,
::  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
::  See the License for the specific language governing permissions and
::  limitations under the License.

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:: Gather necessary paths and clear output dir (if it exists already).
SET ret=%CD%
SET repo=%~dp0
SET out="%repo%\build-msvc"
if exist %out% ( rd /s /q %out% )
mkdir %out% && cd %out% || exit /b

:: Copy header files into output dir.
mkdir include || exit /b
xcopy ..\include .\include || exit /b

:: Build the CECIES CLI programs.
cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DCECIES_ENABLE_TESTS=Off -DCECIES_ENABLE_PROGRAMS=On -DCMAKE_BUILD_TYPE=Release .. || exit /b
cmake --build . --config Release || exit /b

:: Build the DLL.
mkdir dynamic && cd dynamic || exit /b
cmake -DBUILD_SHARED_LIBS=On -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DCECIES_BUILD_DLL=On -DCECIES_ENABLE_PROGRAMS=Off -DCECIES_ENABLE_TESTS=Off -DCMAKE_BUILD_TYPE=Release ..\.. || exit /b
cmake --build . --config Release || exit /b
cd ..

:: Build static lib.
mkdir static && cd static || exit /b
cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DCECIES_BUILD_DLL=Off -DCECIES_ENABLE_PROGRAMS=Off -DCECIES_ENABLE_TESTS=Off -DCMAKE_BUILD_TYPE=Release ..\.. || exit /b
cmake --build . --config Release || exit /b
cd ..

:: Compress the result and return to the original working directory.
tar -czvf cecies.tar.gz programs\Release\*.exe dynamic\Release\* static\Release\*
cd %RET%