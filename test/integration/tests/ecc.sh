# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f pass1_ecc.q pass2_ecc.q ecc.ctr

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

# TPM2_EC_Ephemeral
## Check if commit counter is zero on first invocation
tpm2_ecephermal -u pass1_ecc.q -t pass1_ecc.ctr ecc256
xxd -p pass1_ecc.ctr | grep 0000
## Check if commit counter increments to 1 on second invocation
tpm2_ecephermal -u pass2_ecc.q -t pass2_ecc.ctr ecc256
xxd -p pass2_ecc.ctr | grep 0001

# TPM2_Commit
## Check if commit counter in incremented after successful execution of commit
tpm2_createprimary -C o -c prim.ctx -Q

tpm2_create -C prim.ctx -c commit_key.ctx -u commit_key.pub -r commit_key.priv \
-G ecc256:ecdaa

tpm2_commit -c commit_key.ctx -t commit.ctr --eccpoint-K K.bin \
--eccpoint-L L.bin -u E.bin

xxd -p commit.ctr | grep 0002

# TPM2_ECDH_KeyGen
## Check if ecdhkeygen creates ephemeral key with loaded ECC key of type ECDAA
tpm2_ecdhkeygen -u ecc256ecdaa.pub -o ecc256ecdaa.priv -c commit_key.ctx

## Check if ecdhkeygen creates ephemeral key with loaded ECC key of type ECDH
tpm2_create -C prim.ctx -c ecdh_key.ctx -u ecdh_key.pub -r ecdh_key.priv \
-G ecc256:ecdh

tpm2_ecdhkeygen -u ecc256ecdh.pub -o ecc256ecdh.priv -c ecdh_key.ctx

# TPM2_ECDH_ZGen
## Check if the recovered Z point matches
tpm2_ecdhzgen -u ecc256ecdh.pub -o ecdhZgen.dat -c ecdh_key.ctx

diff ecdhZgen.dat ecc256ecdh.priv

exit 0
