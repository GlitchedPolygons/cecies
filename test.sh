#!/bin/sh

#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

PROJECT_NAME="cecies"
REPO=$(dirname "$0")

PREVCC="$CC"
PREVCXX="$CXX"

if command -v clang &> /dev/null
then
    echo "-- Clang found on system, great! Long live LLVM! :D"
    export CC=clang
    export CXX=clang++
fi

cov=Off
if [ "$1" = "cov" ]; then cov=On; fi
rm -rf "$REPO"/build
mkdir -p "$REPO"/build && cd "$REPO"/build || exit

cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off "-D${PROJECT_NAME}_ENABLE_TESTS=On" -DENABLE_COVERAGE="${cov}" ..
cmake --build . --config Debug || exit

export CC="$PREVCC"
export CXX="$PREVCXX"

./run_tests || ./Debug/run_tests.exe || exit

cd "$REPO" || exit