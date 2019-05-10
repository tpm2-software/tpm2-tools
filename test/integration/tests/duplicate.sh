#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

TPM_CC_DUPLICATE=0x14B

cleanup() {
    rm -f primary.ctx \
          new_parent.prv new_parent.pub new_parent.ctx \
          policy.dat session.dat \
          key.prv key.pub key.ctx \
          duppriv.bin dupseed.dat \
          key2.prv key2.pub key2.ctx \
          sym_key_in.bin

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

create_duplication_policy() {
    tpm2_startauthsession -Q -S session.dat
    tpm2_policycommandcode -Q -S session.dat -o policy.dat $TPM_CC_DUPLICATE
    tpm2_flushcontext -Q -S session.dat
    rm session.dat
}

start_duplication_session() {
    tpm2_startauthsession -Q --policy-session -S session.dat
    tpm2_policycommandcode -Q -S session.dat -o policy.dat $TPM_CC_DUPLICATE
}

end_duplication_session() {
    tpm2_flushcontext -Q -S session.dat
    rm session.dat
}

dump_duplication_session() {
    rm session.dat
}

dd if=/dev/urandom of=sym_key_in.bin bs=1 count=16 status=none

tpm2_createprimary -Q -a o -g sha256 -G rsa -o primary.ctx

# Create a new parent, we will only use the public portion
tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r new_parent.prv -u new_parent.pub -b "decrypt|fixedparent|fixedtpm|restricted|sensitivedataorigin"

# Create the key we want to duplicate
create_duplication_policy
tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r key.prv -u key.pub -L policy.dat -b "sensitivedataorigin|sign|decrypt"
tpm2_load -Q -C primary.ctx -r key.prv -u key.pub -o key.ctx

tpm2_loadexternal -Q -a o -u new_parent.pub -o new_parent.ctx

## Null parent, Null Sym Alg
start_duplication_session
tpm2_duplicate -Q -C null -c key.ctx -g null -p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## Null Sym Alg
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key.ctx -g null -p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## Null parent
start_duplication_session
tpm2_duplicate -Q -C null -c key.ctx -g aes -i sym_key_in.bin -p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## AES Sym Alg, user supplied key
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key.ctx -g aes -i sym_key_in.bin -p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## AES Sym Alg, no user supplied key
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key.ctx -g aes -o sym_key_out.bin -p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## Repeat the tests with a key that requires encrypted duplication
tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r key2.prv -u key2.pub -L policy.dat -b "sensitivedataorigin|sign|decrypt|encryptedduplication"
tpm2_load -Q -C primary.ctx -r key2.prv -u key2.pub -o key2.ctx

## AES Sym Alg, user supplied key
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key2.ctx -g aes -i sym_key_in.bin -p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## AES Sym Alg, no user supplied key
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key2.ctx -g aes -o sym_key_out.bin -p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

trap - ERR

## Null parent - should fail (TPM_RC_HIERARCHY)
start_duplication_session
tpm2_duplicate -Q -C null -c key2.ctx -g aes -i sym_key_in.bin -p "session:session.dat" -r dupprv.bin -s dupseed.dat
if [ $? -eq 0 ]; then
  echo "Expected \"tpm2_duplicate -C null \" to fail."
  exit 1
fi
dump_duplication_session

## Null Sym Alg - should fail (TPM_RC_SYMMETRIC)
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key2.ctx -g null -p "session:session.dat" -r dupprv.bin -s dupseed.dat
if [ $? -eq 0 ]; then
  echo "Expected \"tpm2_duplicate -g null \" to fail."
  exit 1
fi
dump_duplication_session

exit 0
