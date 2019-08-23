# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f primary.ctx new_parent.prv new_parent.pub new_parent.ctx policy.dat \
    session.dat key.prv key.pub key.ctx duppriv.bin dupseed.dat key2.prv \
    key2.pub key2.ctx sym_key_in.bin

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

create_duplication_policy() {
    tpm2_startauthsession -Q -S session.dat
    tpm2_policycommandcode -Q -S session.dat -L policy.dat TPM2_CC_Duplicate
    tpm2_flushcontext -Q session.dat
    rm session.dat
}

start_duplication_session() {
    tpm2_startauthsession -Q --policy-session -S session.dat
    tpm2_policycommandcode -Q -S session.dat -L policy.dat TPM2_CC_Duplicate
}

end_duplication_session() {
    tpm2_flushcontext -Q session.dat
    rm session.dat
}

dump_duplication_session() {
    rm session.dat
}

dd if=/dev/urandom of=sym_key_in.bin bs=1 count=16 status=none

tpm2_createprimary -Q -C o -g sha256 -G rsa -c primary.ctx

# Create a new parent, we will only use the public portion
tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
-u new_parent.pub -a "decrypt|fixedparent|fixedtpm|restricted|\
sensitivedataorigin"

# Create the key we want to duplicate
create_duplication_policy
tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r key.prv -u key.pub \
-L policy.dat -a "sensitivedataorigin|sign|decrypt"
tpm2_load -Q -C primary.ctx -r key.prv -u key.pub -c key.ctx

tpm2_loadexternal -Q -C o -u new_parent.pub -c new_parent.ctx

## Null parent, Null Sym Alg
start_duplication_session
tpm2_duplicate -Q -C null -c key.ctx -G null -p "session:session.dat" \
-r dupprv.bin -s dupseed.dat
end_duplication_session

## Null Sym Alg
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key.ctx -G null \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## Null parent
start_duplication_session
tpm2_duplicate -Q -C null -c key.ctx -G aes -i sym_key_in.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## AES Sym Alg, user supplied key
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key.ctx -G aes -i sym_key_in.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## AES Sym Alg, no user supplied key
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key.ctx -G aes -o sym_key_out.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## Repeat the tests with a key that requires encrypted duplication
tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r key2.prv -u key2.pub \
-L policy.dat -a "sensitivedataorigin|sign|decrypt|encryptedduplication"
tpm2_load -Q -C primary.ctx -r key2.prv -u key2.pub -c key2.ctx

## AES Sym Alg, user supplied key
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key2.ctx -G aes -i sym_key_in.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## AES Sym Alg, no user supplied key
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key2.ctx -G aes -o sym_key_out.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

trap - ERR

## Null parent - should fail (TPM_RC_HIERARCHY)
start_duplication_session
tpm2_duplicate -Q -C null -c key2.ctx -G aes -i sym_key_in.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
if [ $? -eq 0 ]; then
  echo "Expected \"tpm2_duplicate -C null \" to fail."
  exit 1
fi
dump_duplication_session

## Null Sym Alg - should fail (TPM_RC_SYMMETRIC)
start_duplication_session
tpm2_duplicate -Q -C new_parent.ctx -c key2.ctx -G null \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
if [ $? -eq 0 ]; then
  echo "Expected \"tpm2_duplicate -G null \" to fail."
  exit 1
fi
dump_duplication_session

exit 0
