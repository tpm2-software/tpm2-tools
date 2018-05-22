#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
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

source helpers.sh

start_up

cleanup() {

  rm -f policy.bin obj.pub pub.out

  ina "$@" "keep-context"
  if [ $? -ne 0 ]; then
    rm -f context.out
  fi

  ina "$@" "no-shut-down"
  if [ $? -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

cleanup "no-shut-down"

# Keep the algorithm specifiers mixed to test friendly and raw
# values.
for gAlg in `populate_hash_algs mixed`; do
    for GAlg in 0x01 keyedhash ecc 0x25; do
        tpm2_createprimary -Q -g $gAlg -G $GAlg -o context.out
        cleanup "no-shut-down" "keep-context"
        for Atype in o e n; do
            tpm2_createprimary -Q -a $Atype -g $gAlg -G $GAlg -o context.out
            cleanup "no-shut-down" "keep-context"
        done
    done
done

policy_orig="f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988"

#test for createprimary objects with policy authorization structures
echo -n "$policy_orig" | xxd -r -p > policy.bin

tpm2_createprimary -Q -a o -G rsa -g sha256 -o context.out -L policy.bin \
  -A 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin'

tpm2_readpublic -c context.out > pub.out

policy_new=$(yaml_get_kv pub.out \"authorization\ policy\")

test "$policy_orig" == "$policy_new"

# Test that -g/-G do not need to be specified.
tpm2_createprimary -Q -o context.out

exit 0
