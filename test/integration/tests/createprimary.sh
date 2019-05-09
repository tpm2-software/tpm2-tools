#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
# All rights reserved.
#
#;**********************************************************************;

source helpers.sh

start_up

cleanup() {

  rm -f policy.bin obj.pub pub.out primary.ctx

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
for gAlg in `populate_hash_algs 'and alg != "keyedhash"'`; do
    for GAlg in rsa xor ecc aes; do
        echo tpm2_createprimary -Q -g $gAlg -G $GAlg -o context.out
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
  -b 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin'

tpm2_readpublic -c context.out > pub.out

policy_new=$(yaml_get_kv pub.out \"authorization\ policy\")

test "$policy_orig" == "$policy_new"

# Test that -u can be specified to pass a TPMU_PUBLIC_ID union
# in this case TPM2B_PUBLIC_KEY_RSA (256 bytes of zero)
printf '\x00\x01' > ud.1
dd if=/dev/zero bs=256 count=1 of=ud.2
cat ud.1 ud.2 > unique.dat
tpm2_createprimary -a o -G rsa2048:aes128cfb -g sha256 -o prim.ctx \
  -b 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda' \
  -u unique.dat
test -f prim.ctx

# Test that -g/-G do not need to be specified.
tpm2_createprimary -Q -o context.out

# Test that -o does not need to be specified.
tpm2_createprimary -Q
test -f primary.ctx

# Test for session leaks
BEFORE=$(tpm2_getcap -c handles-loaded-session; tpm2_getcap -c handles-saved-session)
tpm2_createprimary -Q
AFTER=$(tpm2_getcap -c handles-loaded-session; tpm2_getcap -c handles-saved-session)
test "${BEFORE}" = "${AFTER}"

exit 0
