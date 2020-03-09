# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f helpers.sh signing_key_private.pem signing_key_public.pem \
    signing_key.ctx signing_key.name authorized.policy policy.dat \
    primary.ctx key.prv key.pub key.ctx new_parent.prv new_parent.pub \
    new_parent.ctx new_parent.name key.name name.hash policy.namehash \
    policynamehash.signature policy.namehash verification.tkt dupprv.bin \
    dupseed.dat

    tpm2_flushcontext session.ctx 2>/dev/null || true
    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

generate_policycphash() {
    tpm2_startauthsession -S session.ctx -g sha256
    tpm2_policycphash -S session.ctx -L policy.cphash --cphash cp.hash
    tpm2_flushcontext session.ctx
    rm session.ctx
}

sign_and_verify_policycphash() {
    openssl dgst -sha256 -sign signing_key_private.pem \
    -out policycphash.signature policy.cphash

    tpm2_verifysignature -c signing_key.ctx -g sha256 -m policy.cphash \
    -s policycphash.signature -t verification.tkt -f rsassa
}

setup_authorized_policycphash() {
    tpm2_startauthsession -S session.ctx --policy-session -g sha256
    tpm2_policycphash -S session.ctx --cphash cp.hash
    tpm2_policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
    -t verification.tkt
}

setup_owner_policy() {
    tpm2_setprimarypolicy -C o -L policy.cphash -g sha256
    tpm2_startauthsession -S session.ctx --policy-session -g sha256
    tpm2_policycphash -S session.ctx --cphash cp.hash
}

start_policy_cphash() {
    tpm2_startauthsession -S session.ctx --policy-session -g sha256
    tpm2_policycphash -S session.ctx --cphash cp.hash
}

create_authorized_policy() {
  tpm2_clear
  # Define an authorized policy for an object
  openssl genrsa -out signing_key_private.pem 2048
  openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout
  tpm2_loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx \
  -n signing_key.name
  tpm2_startauthsession -S session.ctx -g sha256
  tpm2_policyauthorize -S session.ctx -L authorized.policy -n signing_key.name
  tpm2_flushcontext session.ctx
}

# Restrict the value that can be set through tpm2_nvsetbits.
create_authorized_policy
tpm2_nvdefine 1 -a "policywrite|authwrite|ownerread|nt=bits" -L authorized.policy
## Create policycphash
tpm2_nvsetbits 1 -i 1 --cphash cp.hash
generate_policycphash
## Sign and verify policycphash
sign_and_verify_policycphash
## Satisfy policycphash and execute nvsetbits
setup_authorized_policycphash
tpm2_nvsetbits 1 -i 1 -P "session:session.ctx"
tpm2_flushcontext session.ctx
## Attempt setting another bit which was not recorded in policycphash
setup_authorized_policycphash
trap - ERR
tpm2_nvsetbits 1 -i 2 -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: nvsetbits must fail!"
  exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx
tpm2_nvundefine 1

# Test tpm2_nvextend
create_authorized_policy
tpm2_nvdefine 1 -a "nt=extend|ownerread|policywrite" -L authorized.policy
echo "foo" | tpm2_nvextend -i- 1 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
echo "foo" | tpm2_nvextend -i- 1 -P "session:session.ctx"
tpm2_flushcontext session.ctx
## test the failing scenario
setup_authorized_policycphash
trap - ERR
echo "food" | tpm2_nvextend -i- 1 -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: nvextend must fail!"
  exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx
tpm2_nvundefine 1

# Test tpm2_nvincrement
create_authorized_policy
tpm2_nvdefine 1 -s 8 -a "nt=counter|ownerread|policywrite" -L authorized.policy
tpm2_nvincrement 1 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_nvincrement 1 -P "session:session.ctx"
tpm2_flushcontext session.ctx
tpm2_nvundefine 1

# Test tpm2_nvread
create_authorized_policy
tpm2_nvdefine 1 -s 8 -a "ownerwrite|policyread" -L authorized.policy
echo "foo" | tpm2_nvwrite 1 -i- -C o
tpm2_nvread 1 -s 8 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_nvread 1 -s 8 -P "session:session.ctx" | xxd -p
## test the failing scenario
setup_authorized_policycphash
trap - ERR
tpm2_nvread 1 -s 7 --offset 1 -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: nvread must fail!"
  exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx
tpm2_nvundefine 1

# Test tpm2_nvreadlock
create_authorized_policy
tpm2_nvdefine 1 -C o -s 32 -a "policyread|policywrite|read_stclear" \
-L authorized.policy
tpm2_nvreadlock 1 -C 0x01000001 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_nvreadlock 1 -C 0x01000001 -P "session:session.ctx"
tpm2_flushcontext session.ctx
tpm2_nvundefine 1

# Test tpm2_nvwritelock
create_authorized_policy
tpm2_nvdefine 1 -C o -s 32 -a "policyread|policywrite|writedefine" \
-L authorized.policy
tpm2_nvwritelock 1 -C 0x01000001 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_nvwritelock 1 -C 0x01000001 -P "session:session.ctx"
tpm2_flushcontext session.ctx
tpm2_nvundefine 1
## attempt with globallock attribute set
tpm2_nvdefine 1 -C o -s 32 -a "ownerread|ownerwrite|globallock"
tpm2_nvwritelock --global -C o --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2_nvwritelock --global -C o -P "session:session.ctx"
tpm2_flushcontext session.ctx
tpm2_nvundefine 1

# Test tpm2_nvdefine
tpm2_nvdefine 1 -C o -s 32 -a "ownerread|ownerwrite" --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2_nvdefine 1 -C o -s 32 -a "ownerread|ownerwrite" -P "session:session.ctx"
tpm2_flushcontext session.ctx
## attempt failing scenario
start_policy_cphash
trap - ERR
tpm2_nvdefine 2 -C o -s 32 -a "ownerread|ownerwrite" -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: nvdefine must fail!"
  exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx
tpm2_nvundefine 1

# Test tpm2_nvundefine
tpm2_nvdefine 1
tpm2_nvundefine 1 --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2_nvundefine 1 -P "session:session.ctx"
tpm2_flushcontext session.ctx
## attempt failing scenario
tpm2_nvdefine 2
start_policy_cphash
trap - ERR
tpm2_nvundefine 2 -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: nvundefine must fail!"
  exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx
tpm2_nvundefine -C p 2

#Test tpm2_nvcertify
tpm2_createprimary -C o -c primary.ctx -Q
tpm2_create -G rsa -u signing_key.pub -r signing_key.priv -C primary.ctx \
-c signing_key.ctx -Q
tpm2_readpublic -c signing_key.ctx -f pem -o sslpub.pem -Q
tpm2_nvdefine -s 32 -C o -a "ownerread|ownerwrite|authread|authwrite" 1
dd if=/dev/urandom bs=1 count=32 status=none| tpm2_nvwrite 1 -i-
tpm2_nvcertify -C signing_key.ctx -g sha256 -f plain -s rsassa \
-o signature.bin --attestation attestation.bin --size 32 1 -c o --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2_nvcertify -C signing_key.ctx -g sha256 -f plain -s rsassa \
-o signature.bin --attestation attestation.bin --size 32 1 -c o -p "session:session.ctx"
tpm2_flushcontext session.ctx
tpm2_nvundefine 1

#Test tpm2_policynv
tpm2_nvdefine -C o -a "ownerwrite|ownerread" -s 2 1
operandA=0x81
operandB=0x80
echo $operandA | xxd -r -p | tpm2_nvwrite -C o -i- 1
tpm2_startauthsession -S policy_session.ctx --policy-session -g sha256
echo $operandB | xxd -r -p | tpm2_policynv -i- -C o --cphash cp.hash 1 neq -S policy_session.ctx
generate_policycphash
setup_owner_policy
echo $operandB | xxd -r -p | tpm2_policynv -S policy_session.ctx -i- -C o -P "session:session.ctx" 1 neq
tpm2_flushcontext policy_session.ctx
tpm2_flushcontext session.ctx
tpm2_nvundefine 1

# Test tpm2_policyauthorizenv
tpm2_nvdefine -C o 1 -a "ownerread|ownerwrite" -s 34
tpm2_startauthsession -S session.ctx
tpm2_policypassword -S session.ctx -L policy.pass
tpm2_flushcontext session.ctx
POLICYDIGESTALGORITHM=000b
echo $POLICYDIGESTALGORITHM | xxd -p -r | cat - policy.pass | \
tpm2_nvwrite -C o 1 -i-
tpm2_startauthsession -S policy_session.ctx --policy-session
tpm2_policyauthorizenv -S policy_session.ctx -C o 1 --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2_policypassword -S policy_session.ctx
tpm2_policyauthorizenv -S policy_session.ctx -C o 1 -P "session:session.ctx"
tpm2_flushcontext policy_session.ctx
tpm2_flushcontext session.ctx
tpm2_nvundefine 1

# Test tpm2_policysecret
tpm2_startauthsession -S policy_session.ctx --policy-session -g sha256
tpm2_policysecret -S policy_session.ctx -c o --cphash cp.hash
tpm2_startauthsession -S session.ctx -g sha256
tpm2_policyauthvalue -S session.ctx -L policy.authval
tpm2_policycphash -S session.ctx --cphash cp.hash -L policy.authval_cphash
tpm2_flushcontext session.ctx
tpm2_setprimarypolicy -C o -L policy.authval_cphash -g sha256
tpm2_startauthsession -S session.ctx --policy-session -g sha256
tpm2_policyauthvalue -S session.ctx
tpm2_policycphash -S session.ctx --cphash cp.hash
## Changing the policysecret authhandle parameter fro "o" to "p" should fail
tpm2_policysecret -S policy_session.ctx -c o session:session.ctx
tpm2_flushcontext session.ctx
tpm2_flushcontext policy_session.ctx

# Test tpm2_create
create_authorized_policy
tpm2_createprimary -C o -c prim.ctx -G rsa -L authorized.policy
tpm2_create -C prim.ctx -G rsa --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_create -C prim.ctx -G rsa -P "session:session.ctx"
tpm2_flushcontext session.ctx
## Attempt creating a key type that was not recorded in policycphash
setup_authorized_policycphash
trap - ERR
tpm2_create -C prim.ctx -G aes -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: tpm2_create must fail!"
  exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx

# Test tpm2_load
create_authorized_policy
tpm2_createprimary -C o -c prim.ctx -G rsa -L authorized.policy
tpm2_create -C prim.ctx -G rsa -u key.pub -r key.priv
tpm2_create -C prim.ctx -G rsa -u key_2.pub -r key_2.priv
tpm2_load -C prim.ctx -u key.pub -r key.priv --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_load -C prim.ctx -u key.pub -r key.priv -c key.ctx -P "session:session.ctx"
tpm2_flushcontext session.ctx
## Attempt loading another key that was not recorded in policycphash
setup_authorized_policycphash
trap - ERR
tpm2_load -C prim.ctx -u key_2.pub -r key_2.priv -c key_2.ctx \
-P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: tpm2_load must fail!"
  exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx

# Test tpm2_activatecredential
create_authorized_policy
tpm2_createprimary -C o -c prim.ctx -G rsa
tpm2_readpublic -c prim.ctx -o prim.pub
tpm2_create -C prim.ctx -u key.pub -r key.priv -c key.ctx -L authorized.policy
tpm2_readpublic -c key.ctx -n key.name
echo "plaintext" > plain.txt
tpm2_makecredential -e prim.pub  -s plain.txt -n `xxd -p -c 34 key.name` \
-o cred.secret
tpm2_activatecredential -c key.ctx -C prim.ctx -i cred.secret -o act_cred.secret \
--cphash cp.hash
tpm2_startauthsession -S session.ctx -g sha256
tpm2_policycphash -S session.ctx -L policy.cphash --cphash cp.hash
tpm2_policycommandcode -S session.ctx TPM2_CC_ActivateCredential -L policy.cphash
tpm2_flushcontext session.ctx
sign_and_verify_policycphash
tpm2_startauthsession -S session.ctx --policy-session -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_policycommandcode -S session.ctx TPM2_CC_ActivateCredential
tpm2_policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
-t verification.tkt
tpm2_activatecredential -c key.ctx -C prim.ctx -i cred.secret -o act_cred.secret \
-p "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_unseal
create_authorized_policy
tpm2_createprimary -C o -c prim.ctx
echo "plaintext" | \
tpm2_create -C prim.ctx -c key.ctx -u key.pub -r key.priv -L authorized.policy -i-
tpm2_unseal -c key.ctx --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_unseal -c key.ctx -p "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_changeauth
tpm2_clear
tpm2_changeauth -c o ownerpassword --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2_changeauth -c o ownerpassword -p session:session.ctx
tpm2_flushcontext session.ctx
## Negative test
tpm2_clear
tpm2_changeauth -c o ownerpassword --cphash cp.hash
generate_policycphash
setup_owner_policy
trap - ERR
tpm2_changeauth -c o wrongownerpassword -p session:session.ctx
if [ $? == 0 ];then
  echo "ERROR: tpm2_load must fail!"
  exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx

#Test tpm2_duplicate
create_authorized_policy
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_create -C primary.ctx -g sha256 -G rsa -r duplicable_key.prv \
-u duplicable_key.pub -a "sensitivedataorigin|sign|decrypt|encryptedduplication" \
-L authorized.policy
tpm2_load -C primary.ctx -r duplicable_key.prv -u duplicable_key.pub \
-c duplicable_key.ctx
tpm2_create -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
-u new_parent.pub -a "decrypt|fixedparent|fixedtpm|restricted|\
sensitivedataorigin"
tpm2_loadexternal -C o -u new_parent.pub -c new_parent.ctx
dd if=/dev/urandom of=sym_key_in.bin bs=1 count=16 status=none
tpm2_duplicate -C new_parent.ctx -c duplicable_key.ctx -G aes \
-i sym_key_in.bin -r dupprv.bin -s dupseed.dat --cphash cp.hash
tpm2_startauthsession -S session.ctx -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_policycommandcode -S session.ctx -L policy.cphash TPM2_CC_Duplicate
tpm2_flushcontext session.ctx
sign_and_verify_policycphash
tpm2_startauthsession --policy-session -S session.ctx -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_policycommandcode -S session.ctx TPM2_CC_Duplicate
tpm2_policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
-t verification.tkt
tpm2_duplicate -C new_parent.ctx -c duplicable_key.ctx -G aes \
-i sym_key_in.bin -r dupprv.bin -s dupseed.dat -p "session:session.ctx"
tpm2_flushcontext session.ctx
## attempt failing scenario
dd if=/dev/urandom of=sym_key_in.bin bs=1 count=16 status=none
tpm2_startauthsession --policy-session -S session.ctx -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_policycommandcode -S session.ctx TPM2_CC_Duplicate
tpm2_policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
-t verification.tkt
trap - ERR
tpm2_duplicate -C new_parent.ctx -c duplicable_key.ctx -G aes \
-i sym_key_in.bin -r dupprv.bin -s dupseed.dat -p "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: tpm2_duplicate must fail!"
  exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx

# Test tpm2_import
create_authorized_policy
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_create -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
-u new_parent.pub -c new_parent.ctx -L authorized.policy \
-a "restricted|sensitivedataorigin|decrypt|userwithauth"
tpm2_startauthsession -S session.ctx
tpm2_policycommandcode -S session.ctx -L dpolicy.dat TPM2_CC_Duplicate
tpm2_flushcontext session.ctx
tpm2_create -C primary.ctx -g sha256 -G rsa -p foo -r dupkey.prv -u dupkey.pub \
-L dpolicy.dat -a "sensitivedataorigin|decrypt|userwithauth" -c dupkey.ctx
tpm2_startauthsession --policy-session -S session.ctx
tpm2_policycommandcode -S session.ctx TPM2_CC_Duplicate
tpm2_duplicate -C new_parent.ctx -c dupkey.ctx -G null -p "session:session.ctx" \
-r duplicated.prv -s dup.seed
tpm2_flushcontext session.ctx
tpm2_import -C new_parent.ctx -u dupkey.pub -i duplicated.prv -r imported_dup.prv \
-s dup.seed --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_import -C new_parent.ctx -u dupkey.pub -i duplicated.prv -r imported_dup.prv \
-s dup.seed -P "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_rsadecrypt
create_authorized_policy
tpm2_createprimary -C o -c prim.ctx
tpm2_create -C prim.ctx -c key.ctx -u key.pub -r key.priv -L authorized.policy \
-G rsa
echo "plaintext" > plain.txt
tpm2_rsaencrypt -c key.ctx -o enc.out plain.txt
tpm2_rsadecrypt -c key.ctx -s rsaes enc.out --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_rsadecrypt -c key.ctx -s rsaes enc.out -o dec.out -p "session:session.ctx"
tpm2_flushcontext session.ctx
# Attempt failing case
dd if=/dev/urandom of=rand.om bs=1 count=256 status=none
setup_authorized_policycphash
trap - ERR
tpm2_rsadecrypt -c key.ctx -s rsaes rand.om -o dec.out -p "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: tpm2_rsadecrypt must fail!"
  exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx

# Test tpm2_certify
create_authorized_policy
tpm2_createprimary -C o -G rsa -g sha256 -c prim.ctx -p primarypass
tpm2_create -C prim.ctx -c key.ctx -G rsa  -u key.pub -r key.priv \
-L authorized.policy -P primarypass
tpm2_certify -c prim.ctx -C key.ctx -g sha256 --cphash cp.hash
tpm2_startauthsession -S session.ctx -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_policycommandcode -S session.ctx -L policy.cphash TPM2_CC_Certify
tpm2_flushcontext session.ctx
sign_and_verify_policycphash
tpm2_startauthsession --policy-session -S session.ctx -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_policycommandcode -S session.ctx TPM2_CC_Certify
tpm2_policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
-t verification.tkt
tpm2_certify -c prim.ctx -C key.ctx -g sha256 -o attest.out -s sig.out \
-p "session:session.ctx" -P primarypass
tpm2_flushcontext session.ctx

# Test tpm2_certifycreation
create_authorized_policy
tpm2_createprimary -C o -c prim.ctx --creation-data create.dat \
-d create.dig -t create.ticket
tpm2_create -G rsa -u rsa.pub -r rsa.priv -C prim.ctx -c signingkey.ctx \
-L authorized.policy
tpm2_certifycreation -C signingkey.ctx -c prim.ctx -d create.dig \
-t create.ticket -g sha256 -f plain -s rsassa --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_certifycreation -C signingkey.ctx -c prim.ctx -d create.dig \
-t create.ticket -g sha256 -o sig.nature --attestation attestat.ion -f plain \
-s rsassa -P "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_quote
create_authorized_policy
tpm2_createprimary -C e -c primary.ctx
tpm2_create -C primary.ctx -u key.pub -r key.priv -c key.ctx \
-L authorized.policy
tpm2_quote -Q -c key.ctx -l 0x0004:16,17,18+0x000b:16,17,18 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_quote -Q -c key.ctx -l 0x0004:16,17,18+0x000b:16,17,18 \
-p "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_gettime
create_authorized_policy
tpm2_createprimary -C e -c primary.ctx
tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx \
-c rsa.ctx -L authorized.policy
tpm2_gettime -c rsa.ctx -q "cafebabe" --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_gettime -c rsa.ctx -q "cafebabe" -o attest.sig --attestation attest.data \
-p "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_sign
create_authorized_policy
tpm2_createprimary -C e -c primary.ctx
tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx -c rsa.ctx \
-L authorized.policy
echo "my message" > message.dat
tpm2_sign -c rsa.ctx -g sha256 message.dat --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_sign -c rsa.ctx -g sha256 message.dat -o signature.dat \
-p "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_createprimary
tpm2_clear
tpm2_createprimary -C o -q "cafebabe" --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2_createprimary -C o -q "cafebabe" -P "session:session.ctx" -c prim.ctx
tpm2_flushcontext session.ctx

# Test tpm2_hierarchycontrol
tpm2_clear
tpm2_hierarchycontrol -C p shEnable clear --cphash cp.hash
generate_policycphash
tpm2_setprimarypolicy -C p -L policy.cphash -g sha256
tpm2_startauthsession -S session.ctx --policy-session -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_hierarchycontrol -C p shEnable clear -P "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_setprimarypolicy
tpm2_startauthsession -S session.ctx
tpm2_policyauthvalue -S session.ctx -L policy.authvalue
tpm2_flushcontext session.ctx
create_authorized_policy
tpm2_setprimarypolicy -C o -L authorized.policy -g sha256
tpm2_setprimarypolicy -C o -L policy.authvalue -g sha256 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_setprimarypolicy -C o -L policy.authvalue -g sha256 -P "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_clear
tpm2_clear
tpm2_clear -c l --cphash cp.hash
generate_policycphash
tpm2_setprimarypolicy -C l -L policy.cphash -g sha256
tpm2_startauthsession -S session.ctx --policy-session -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_clear -c l "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_clearcontrol
tpm2_clear
tpm2_clearcontrol -C l s --cphash cp.hash
generate_policycphash
tpm2_setprimarypolicy -C l -L policy.cphash -g sha256
tpm2_startauthsession -S session.ctx --policy-session -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_clearcontrol -C l s -P "session:session.ctx"
tpm2_flushcontext session.ctx

# Test tpm2_dictionarylockout
tpm2_clearcontrol -C p c
tpm2_clear
tpm2_dictionarylockout -s -n 5 -t 6 -l 7 --cphash cp.hash
generate_policycphash
tpm2_setprimarypolicy -C l -L policy.cphash -g sha256
tpm2_startauthsession -S session.ctx --policy-session -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_dictionarylockout -s -n 5 -t 6 -l 7 --cphash cp.hash -p "session:session.ctx"
tpm2_flushcontext session.ctx

# Test evictcontrol
tpm2_clear
tpm2_createprimary -C o -c prim.ctx
tpm2_evictcontrol -C o -c prim.ctx 0x81010001 --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2_evictcontrol -C o -c prim.ctx 0x81010001 -P "session:session.ctx"
tpm2_flushcontext session.ctx

# Test clockset
tpm2_clear
let clockset=`tpm2_readclock | grep clock | grep -v info | awk '{print $2}'`+100000
tpm2_setclock -c o $clockset --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2_setclock -c o $clockset -p "session:session.ctx"
tpm2_flushcontext session.ctx

# Test clockrateadjust
tpm2_clear
tpm2_clockrateadjust s --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2_clockrateadjust s -p "session:session.ctx"
tpm2_flushcontext session.ctx

# Test nvwrite
 create_authorized_policy
 tpm2_nvdefine 1 -s 8 -a "ownerread|authwrite|policywrite" -L authorized.policy
 echo "foo" | tpm2_nvwrite 1 -i- --cphash cp.hash
 xxd -p cp.hash
 generate_policycphash
 sign_and_verify_policycphash
 setup_authorized_policycphash
 echo "foo" | tpm2_nvwrite 1 -i- -P "session:session.ctx"
 tpm2_flushcontext session.ctx

 # Test encryptdecrypt
create_authorized_policy
tpm2_createprimary -Q -C e -g sha1 -G rsa -c primary.ctx
tpm2_create -Q -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx \
-c decrypt.ctx -L authorized.policy

dd if=/dev/urandom of=iv.dat bs=16 count=1
echo "plaintext" > secret.dat
cat secret.dat | tpm2_encryptdecrypt -c decrypt.ctx --iv iv.dat --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_encryptdecrypt -c decrypt.ctx --iv iv.dat:iv2.dat \
-p "session:session.ctx" > secret2.dat

# Test tpm2_hmac
create_authorized_policy
tpm2_createprimary -Q -C o -c prim.ctx
tpm2_create -Q -C prim.ctx -c key.ctx -u key.pub -r key.priv -G hmac \
-L authorized.policy
echo "testdata" > plain.txt
tpm2_hmac -c key.ctx plain.txt --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2_hmac -c key.ctx plain.txt -o hmac.bin -p "session:session.ctx"
tpm2_flushcontext session.ctx

exit 0
