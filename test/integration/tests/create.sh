#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
  rm -f key.pub key.priv policy.bin out.pub key.ctx

  ina "$@" "keep-context"
  if [ $? -ne 0 ]; then
    rm -f context.out
  fi

  rm -f key*.ctx out.yaml

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
for gAlg in `populate_hash_algs`; do
    for GAlg in rsa 0x08 ecc 0x25; do
        echo "tpm2_create -Q -C context.out -g $gAlg -G $GAlg -u key.pub -r key.priv"
        tpm2_create -Q -C context.out -g $gAlg -G $GAlg -u key.pub -r key.priv
        cleanup "keep-context" "no-shut-down"
    done
done

cleanup "keep-context" "no-shut-down"

policy_orig="f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988"
echo "$policy_orig" | xxd -r -p > policy.bin

tpm2_create -C context.out -g sha256 -G 0x1 -L policy.bin -u key.pub -r key.priv \
  -b 'sign|fixedtpm|fixedparent|sensitivedataorigin' > out.pub

policy_new=$(yaml_get_kv out.pub \"authorization\ policy\")

test "$policy_orig" == "$policy_new"

#
# Test the extended format specifiers
#
tpm2_create -Q -C context.out -g sha256 -G aes256cbc -u key.pub -r key.priv
tpm2_load -Q -C context.out -u key.pub -r key.priv -o key1.ctx
tpm2_readpublic -c key1.ctx > out.yaml
keybits=$(yaml_get_kv out.yaml \"sym-keybits\")
mode=$(yaml_get_kv out.yaml \"sym-mode\" \"value\")
test "$keybits" -eq "256"
test "$mode" == "cbc"

tpm2_create -Q -C context.out -g sha256 -G aes128ofb -u key.pub -r key.priv
tpm2_load -Q -C context.out -u key.pub -r key.priv -o key2.ctx
tpm2_readpublic -c key2.ctx > out.yaml
keybits=$(yaml_get_kv out.yaml \"sym-keybits\")
mode=$(yaml_get_kv out.yaml \"sym-mode\" \"value\")
test "$keybits" -eq "128"
test "$mode" == "ofb"

#
# Test scheme support
#

for alg in "rsa1024:rsaes" "ecc384:ecdaa4-sha256"; do
  tpm2_create -Q -C context.out -g sha256 -G "$alg" -u key.pub -r key.priv
done

# Test createloaded support
tpm2_create -C context.out -u key.pub -r key.priv -o key.ctx
tpm2_readpublic -c key.ctx 2>/dev/null

exit 0
