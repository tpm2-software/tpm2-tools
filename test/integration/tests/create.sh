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

cleanup() {
  rm -f key.pub key.priv policy.bin out.pub

  ina "$@" "keep-context"
  if [ $? -ne 0 ]; then
    rm -f context.out
  fi

  rm -f key.ctx out.yaml

  ina "$@" "no-shut-down"
  if [ $? -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_createprimary -Q -a o -g sha1 -G rsa -o context.out

# Keep the algorithm specifiers mixed to test friendly and raw
# values.
for gAlg in `populate_hash_algs mixed`; do
    for GAlg in rsa 0x08 ecc 0x25; do
        tpm2_create -Q -C context.out -g $gAlg -G $GAlg -u key.pub -r key.priv
        cleanup "keep-context" "no-shut-down"
    done
done

cleanup "keep-context" "no-shut-down"

policy_orig="f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988"
echo "$policy_orig" | xxd -r -p > policy.bin

tpm2_create -C context.out -g sha256 -G 0x1 -L policy.bin -u key.pub -r key.priv \
  -A 'sign|fixedtpm|fixedparent|sensitivedataorigin' > out.pub

policy_new=$(yaml_get_kv out.pub \"authorization\ policy\")

test "$policy_orig" == "$policy_new"

#
# Test the extended format specifiers
#
tpm2_create -Q -C context.out -g sha256 -G aes256cbc -u key.pub -r key.priv
tpm2_load -Q -C context.out -u key.pub -r key.priv -o key.ctx
tpm2_readpublic -c key.ctx > out.yaml
keybits=$(yaml_get_kv out.yaml \"keybits\")
mode=$(yaml_get_kv out.yaml \"mode\" \"value\")
test "$keybits" -eq "256"
test "$mode" == "cbc"

tpm2_create -Q -C context.out -g sha256 -G aes128ofb -u key.pub -r key.priv
tpm2_load -Q -C context.out -u key.pub -r key.priv -o key.ctx
tpm2_readpublic -c key.ctx > out.yaml
keybits=$(yaml_get_kv out.yaml \"keybits\")
mode=$(yaml_get_kv out.yaml \"mode\" \"value\")
test "$keybits" -eq "128"
test "$mode" == "ofb"


exit 0
