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

#!/bin/bash

SRC_DIR=`realpath ../../tools/`
TEST_DIR=`realpath .`
PATH=$SRC_DIR:$PATH
PATH=$TEST_DIR:$PATH

pass=0
fail=0

fail_summary=""

test_wrapper()
{
  ./$1
  if [ $? -eq 0 ]; then
    echo -e "\033[32m $1 pass \033[0m"
    let "pass++"
  else
    echo -e "\033[31m $1 Fail \033[0m"
    let "fail++"
    fail_summary="$fail_summary"$'\n'"$1"
  fi

  # Scripts are sloppy, perform cleanup
  rm `find . -maxdepth 1 -type f ! -name '*.sh' ! -name 'README.md' ! -name 'yaml_get.py'` 2>/dev/null
  sleep 1
}

test_wrapper test_tpm2_takeownership_all.sh
test_wrapper test_tpm2_nv.sh
test_wrapper test_tpm2_pcrlist.sh
test_wrapper test_tpm2_getrandom.sh
#test_wrapper test_tpm2_createprimary_all.sh
#test_wrapper test_tpm2_create_all.sh
test_wrapper test_tpm2_load.sh
test_wrapper test_tpm2_loadexternal.sh
test_wrapper test_tpm2_evictcontrol.sh
test_wrapper test_tpm2_hash.sh
test_wrapper test_tpm2_hmac.sh
test_wrapper test_tpm2_quote.sh
test_wrapper test_tpm2_unseal.sh
test_wrapper test_tpm2_akparse.sh
test_wrapper test_tpm2_certify.sh
test_wrapper test_tpm2_evictcontrol.sh
test_wrapper test_tpm2_getpubek.sh
test_wrapper test_tpm2_getpubak.sh
test_wrapper test_tpm2_makecredential.sh
test_wrapper test_tpm2_activecredential.sh
test_wrapper test_tpm2_readpublic.sh
test_wrapper test_tpm2_rsaencrypt.sh
test_wrapper test_tpm2_rsadecrypt.sh
test_wrapper test_tpm2_encryptdecrypt.sh
test_wrapper test_tpm2_sign.sh
test_wrapper test_tpm2_verifysignature.sh
test_wrapper test_tpm2_send_command.sh
test_wrapper test_tpm2_dump_capability.sh
test_wrapper test_tpm2_startup.sh
test_wrapper test_tpm2_pcrevent.sh

# Building with asan on clang, the leak sanitizier
# portion (lsan) on ancient versions is:
# 1. Detecting a leak that (maybe) doesn't exist.
#    OpenSSL is hard...
# 2. The suppresion option via ASAN_OPTIONS doesn't
#    exist for 3.6.
# TODO When this is fixed, remove it.
# Bug: https://github.com/01org/tpm2-tools/issues/390
if [ "$ASAN_ENABLED" != "true" ]; then
  test_wrapper test_tpm2_getmanufec.sh
fi

test_wrapper test_tpm2_dictionarylockout.sh
test_wrapper test_tpm2_createpolicy.sh
test_wrapper test_tpm2_pcrextend.sh
test_wrapper test_tpm2_rc_decode.sh

echo -e "\033[32m Tests passed: $pass \033[0m"
echo -e "\033[31m Tests Failed: $fail  \033[0m"

if [ $fail -gt 0 ]; then
  echo "Fail summary:"
  echo -e "$fail_summary"
fi

exit $fail
