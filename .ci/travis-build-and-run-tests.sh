#!/usr/bin/env bash

# all command failures are fatal
set -e

# Do not run tests when building on coverity_scan branch
if [ "${COVERITY_SCAN_BRANCH}" == 1 ]; then
  echo "Coverity scan branch detected, not running build nor tests...exiting!"
  exit 0
fi

# Bootstrap in the tpm2.0-tss tools directory
./bootstrap

# Make a build variant directory and change to it
mkdir ./build
pushd ./build

# Test building without tcti tabrmd
../configure --enable-unit --without-tcti-tabrmd
make -j$(nproc)
make -j$(nproc) check
make -j$(nproc) clean

# Test building without tcti socket
../configure --enable-unit --without-tcti-socket
make -j$(nproc)
make -j$(nproc) check
make -j$(nproc) clean

# Test building wihtout tcti device
../configure --enable-unit --without-tcti-device
make -j$(nproc)
make -j$(nproc) check
make -j$(nproc) clean

# Build all device TCTIs
../configure --enable-unit
make -j$(nproc)
make -j$(nproc) check
# no clean here, keep artifacts for system testing

# Move out of build back to the tpm2.0-tools directory
popd

# Switch over to the test directory
pushd ./test/system

# Run the tests on ALL device TCTIs configuration
PATH=$(pwd)/../../build/tools:${PATH} ./test_all.sh

# done go back to tpm2.0-tools directory
popd

exit 0
