#;**********************************************************************;
#
# Copyright (c) 2017, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;
#!/usr/bin/env bash

# all command failures are fatal
set -e

if [ -d build ]; then
  rm -rf build
fi

# Do not run tests when building on coverity_scan branch
if [ "${COVERITY_SCAN_BRANCH}" == 1 ]; then
  echo "Coverity scan branch detected, not running build nor tests...exiting!"
  exit 0
fi

# If it's clang, enable asan
if [[ "$CC" == clang* ]]; then
  echo "Detecting clang, enable asan"
  export CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer"
  echo "Exported CFLAGS=$CFLAGS"
  config_flags="--disable-hardening"
  echo "Disabled configure option hardening"
  export ASAN_ENABLED=true
  echo "Exported ASAN_ENABLED=$ASAN_ENABLED"
  # To get line numbers set up the asan symbolizer
  clang_version=`$CC --version | head -n 1 | cut -d\  -f 3-3 | cut -d\. -f 1-2`
  # Sometimes the version string has an Ubuntu on the front of it and the field
  # location changes
  if [ $clang_version == "version" ]; then
    clang_version=`$CC --version | head -n 1 | cut -d\  -f 4-4 | cut -d\. -f 1-2`
  fi
  echo "Detected clang version: $clang_version"
  ASAN_SYMBOLIZER_PATH="/usr/lib/llvm-$clang_version/bin/llvm-symbolizer"
  if [ -e "$ASAN_SYMBOLIZER_PATH" ]; then
    export ASAN_SYMBOLIZER_PATH
    echo "Exported ASAN_SYMBOLIZER_PATH=$ASAN_SYMBOLIZER_PATH"
  else
    echo "No llvm symbolizer found at: $ASAN_SYMBOLIZER_PATH"
    unset ASAN_SYMBOLIZER_PATH
  fi
else #GCC
  export ENABLE_COVERAGE=true
  echo "Exported ENABLE_COVERAGE=true"
fi

# Bootstrap in the tpm2.0-tss tools directory
./bootstrap

# clang has asan enabled with options exported that fail
# make distcheck, so only do this with gcc.
# Do a make distcheck in the root, clear it and than
# cd to the variant directory.
if [ "$CC" == "gcc" ]; then
    ./configure
    make distcheck
    make distclean
fi

# Make a build variant directory and change to it
mkdir ./build
pushd ./build

# Test building without tcti tabrmd
../configure --enable-unit --without-tcti-tabrmd $config_flags

make -j$(nproc)
make -j$(nproc) check
make -j$(nproc) clean

# Test building without tcti socket
../configure --enable-unit --without-tcti-socket $config_flags
make -j$(nproc)
make -j$(nproc) check
make -j$(nproc) clean

# Test building wihtout tcti device
../configure --enable-unit --without-tcti-device $config_flags
make -j$(nproc)
make -j$(nproc) check
make -j$(nproc) clean

# Build all device TCTIs
../configure --enable-unit $config_flags
make -j$(nproc)
make -j$(nproc) check

if [ "$ENABLE_COVERAGE" == "true" ]; then
  # clean before build with coverage
  make clean

  # Build all device TCTIs with gcov
  ../configure --disable-hardening --enable-code-coverage
  make -j$(nproc)
  make -j$(nproc) check
fi
# no clean here, keep artifacts for system testing

# Move out of build back to the tpm2-tools directory
popd

# Switch over to the test directory
pushd ./test/system

# Run the tests on ALL device TCTIs configuration
PATH=$(pwd)/../../build/tools:${PATH} ./test.sh -p

# done go back to tpm2-tools directory
popd

# upload coveralls results
./.ci/coveralls-upload.sh

exit 0
