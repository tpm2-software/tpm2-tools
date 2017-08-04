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
fi

# Bootstrap in the tpm2.0-tss tools directory
./bootstrap

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
# no clean here, keep artifacts for system testing

# Move out of build back to the tpm2-tools directory
popd

# Switch over to the test directory
pushd ./test/system

# Run the tests on ALL device TCTIs configuration
PATH=$(pwd)/../../build/tools:${PATH} ./test_all.sh

# done go back to tpm2-tools directory
popd

exit 0
