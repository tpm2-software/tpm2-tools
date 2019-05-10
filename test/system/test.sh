#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2016, Intel Corporation
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

# We Assume that the tests are run from the system/test location.
SRC_DIR=`realpath ../../tools/`
PATH=$SRC_DIR:$PATH

# Some test helpers are in the test directory
# and might be needed on PATH
TEST_DIR=`realpath .`
PATH=$TEST_DIR:$PATH

# Keep track of failures and successes for reporting
pass=0
fail=0

# Keep track of failed test scripts.
fail_summary=""

red=$'\e[1;31m'
grn=$'\e[1;32m'
yel=$'\e[1;33m'
blu=$'\e[1;34m'
mag=$'\e[1;35m'
cyn=$'\e[1;36m'
end=$'\e[0m'

# Set the default to print in a prety output
PRETTY=true

clear_colors() {
  red=''
  grn=''
  yel=''
  blu=''
  mag=''
  cyn=''
  end=''
}

test_wrapper() {

  ./$1 &
  # Process Id of the previous running command
  pid=$!
  spin='-\|/'
  i=0
  while kill -0 $pid 2>/dev/null; do
    if [ "$PRETTY" == true ]; then
      i=$(( (i+1) %4 ))
      printf "\r${yel}${spin:$i:1}${end}"
      sleep .1
    fi
  done

  wait $pid
  if [ $? -eq 0 ]; then
    printf "\r${grn}$1 ... PASSED${end}\n"
    let "pass++"
  else
    printf "\r${red}$1 ... FAILED${end}\n"
    let "fail++"
    fail_summary="$fail_summary"$'\n'"$1"
  fi
}

# Get a list of test scripts, all tests should begin with test_tpm2_ and
# be a shell script.
tests=`ls test_tpm2_*.sh test_output_formats.sh`

# Building with asan on clang, the leak sanitizier
# portion (lsan) on ancient versions is:
# 1. Detecting a leak that (maybe) doesn't exist.
#    OpenSSL is hard...
# 2. The suppression option via ASAN_OPTIONS doesn't
#    exist for 3.6.
# TODO When this is fixed, remove it.
# Bug: https://github.com/01org/tpm2-tools/issues/390
if [ "$ASAN_ENABLED" == "true" ]; then
  tests=`echo $tests | grep -v test_tpm2_getmanufec.sh`
fi

while true; do
  case "$1" in
    -p | --plain ) PRETTY=false; shift ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

# If command line arguments are provided, assume it is
# the test suite to execute.
# IE: test_tpm2_getrandom.sh
if [ "$#" -gt 0 ]; then
  tests="$@"
fi

if [ "$PRETTY" != true ]; then
  clear_colors
fi

for t in $tests; do
  test_wrapper $t;
done;

# Report the status of the tests
printf "${grn}Tests passed: $pass${end}\n"
printf "${red}Tests Failed: $fail${end}\n"

if [ $fail -gt 0 ]; then
  echo "Fail summary:"
  echo "$fail_summary"
fi

exit $fail
