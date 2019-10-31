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

# Define an authorized policy for an object
openssl genrsa -out signing_key_private.pem 2048
openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout
tpm2_loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx \
-n signing_key.name
tpm2_startauthsession -S session.ctx -g sha256
tpm2_policyauthorize -S session.ctx -L authorized.policy -n signing_key.name
tpm2_flushcontext session.ctx


# Restrict the value that can be set through tpm2_nvsetbits.
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

exit 0
