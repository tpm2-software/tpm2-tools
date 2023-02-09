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

# TPM2_ECC_Parameters
## Check cpHash output for TPM2_ECC_Parameters
tpm2 geteccparameters ecc256 -o ecc.params --cphash cp.hash
TPM2_CC_ECC_Parameters="00000178"
Param_curveID="0003"

echo -ne $TPM2_CC_ECC_Parameters$Param_curveID | xxd -r -p | \
openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2


# TPM2_EC_Ephemeral
## Check if commit counter is zero on first invocation
tpm2 ecephemeral -u pass1_ecc.q -t pass1_ecc.ctr ecc256
xxd -p pass1_ecc.ctr | grep 0000
## Check if commit counter increments to 1 on second invocation
tpm2 ecephemeral -u pass2_ecc.q -t pass2_ecc.ctr ecc256
xxd -p pass2_ecc.ctr | grep 0001

## Check cpHash output for TPM2_EC_Ephemeral
tpm2 ecephemeral -u pass1_ecc.q -t pass1_ecc.ctr ecc256 --cphash cp.hash
TPM2_CC_EC_Ephemeral="0000018e"
Param_curveID="0003"

echo -ne $TPM2_CC_EC_Ephemeral$Param_curveID | xxd -r -p | \
openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2

# TPM2_Commit
## Check if commit counter in incremented after successful execution of commit
tpm2 createprimary -C o -c prim.ctx -Q

tpm2 create -C prim.ctx -c commit_key.ctx -u commit_key.pub -r commit_key.priv \
-G ecc256:ecdaa

tpm2 commit -c commit_key.ctx -t commit.ctr --eccpoint-K K.bin \
--eccpoint-L L.bin -u E.bin

xxd -p commit.ctr | grep 0002

# TPM2_ECDH_KeyGen
## Check if ecdhkeygen creates ephemeral key with loaded ECC key of type ECDAA
tpm2 ecdhkeygen -u ecc256ecdaa.pub -o ecc256ecdaa.priv -c commit_key.ctx

## Check if ecdhkeygen creates ephemeral key with loaded ECC key of type ECDH
tpm2 create -C prim.ctx -c ecdh_key.ctx -u ecdh_key.pub -r ecdh_key.priv \
-G ecc256:ecdh

tpm2 ecdhkeygen -u ecc256ecdh.pub -o ecc256ecdh.priv -c ecdh_key.ctx

## Test cpHash calculation for ecdhkeygen
tpm2 ecdhkeygen -u ecc256ecdh.pub -o ecc256ecdh.priv -c ecdh_key.ctx --cphash cp.hash
name="$(tpm2 readpublic -c ecdh_key.ctx | grep '^name:' | cut -d ' ' -f2)"

cc="00000163"
buffer="${cc}${name}"
echo -n "${buffer}" | xxd -r -p -c256 | openssl dgst -sha256 -binary > expected.hash
cmp cp.hash expected.hash 2

tpm2 ecdhkeygen -u ecc256ecdh.pub -o ecc256ecdh.priv -c ecdh_key.ctx --cphash "sha384:cp.hash"
echo -n "${buffer}" | xxd -r -p -c256 | openssl dgst -sha384 -binary > expected.hash
cmp cp.hash expected.hash 2

# TPM2_ECDH_ZGen
## Check if the recovered Z point matches
tpm2 ecdhzgen -u ecc256ecdh.pub -o ecdhZgen.dat -c ecdh_key.ctx

diff ecdhZgen.dat ecc256ecdh.priv

## Check cpHash output for TPM2_ECDH_ZGen
tpm2 ecdhzgen -u ecc256ecdh.pub -o ecdhZgen.dat -c ecdh_key.ctx --cphash cp.hash
TPM2_CC_ECDH_ZGen="00000154"
tpm2 readpublic -Q -c ecdh_key.ctx -n cp_hash_zgen_key.name
Key_Name=$(xxd -p -c64 cp_hash_zgen_key.name)
Param_inPoint=$(xxd -p -c64 ecc256ecdh.pub )

echo -ne $TPM2_CC_ECDH_ZGen$Key_Name$Param_inPoint | xxd -r -p | \
openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2

# TPM2_ZGen_2Phase
## Check if output Z points are generated using separate commit count values
tpm2 zgen2phase -c ecdh_key.ctx --static-public ecc256ecdh.pub \
--ephemeral-public pass1_ecc.q -t 0 --output-Z1 pass1.z1 --output-Z2 pass1.z2

tpm2 zgen2phase -c ecdh_key.ctx --static-public ecc256ecdh.pub \
--ephemeral-public pass2_ecc.q -t 1 --output-Z1 pass2.z1 --output-Z2 pass2.z2

tpm2 zgen2phase -c ecdh_key.ctx --static-public ecc256ecdh.pub \
--ephemeral-public E.bin -t 2 --output-Z1 pass3.z1 --output-Z2 pass3.z2

## Check to ensure the Z1 points are always the same value
diff pass1.z1 pass2.z1
diff pass2.z1 pass3.z1

## Check to ensure the Z2 points are different
trap - ERR

diff pass1.z2 pass2.z2
diff pass1.z2 pass3.z2
diff pass2.z2 pass3.z2

trap onerror ERR

# Test for cpHash with TPM2_CC_Commit
tpm2 create -C prim.ctx -c cp_hash_commit_key.ctx -u cp_hash_commit_key.pub \
    -r cp_hash_commit_key.priv -G ecc256:ecdaa

tpm2 commit -c cp_hash_commit_key.ctx --cphash cp.hash

TPM2_CC_Commit="0000018B"
tpm2 readpublic -Q -c cp_hash_commit_key.ctx -n cp_hash_commit_key.name
Key_Name=$(xxd -p -c64 cp_hash_commit_key.name)
Param_P1="00040000000000000000"

echo -ne $TPM2_CC_Commit$Key_Name$Param_P1 | xxd -r -p | \
openssl dgst -sha256 -binary -out test.bin

cmp cp.hash test.bin 2

# Test ecdhzgen with public keys instead of public points
tpm2 createprimary -C o -c prim.ctx -Q

# Create ECDH keypair A
tpm2 create -C prim.ctx -c keyA.ctx -u ecdhA.pub -G ecc256:ecdh

# Create ECDH keypair B
tpm2 create -C prim.ctx -c keyB.ctx -u ecdhB.pub -G ecc256:ecdh

# Derive ECDH secret 1 using private key A and public key B
tpm2 ecdhzgen -c keyA.ctx -k ecdhB.pub -o secret1.dat

# Derive ECDH secret 2 using private key B and public key A
tpm2 ecdhzgen -c keyB.ctx -k ecdhA.pub -o secret2.dat
diff secret1.dat secret2.dat

exit 0
