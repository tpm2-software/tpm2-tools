# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f session.ctx secret.dat private.pem public.pem signature.dat \
    signing_key.ctx policy.signed prim.ctx sealing_key.priv sealing_key.pub \
    unsealed.dat unsealed_2.dat qual.dat

    tpm2_flushcontext $session_ctx 2>/dev/null || true

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

# Create the signing authority
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
# Load the verification key and Create the policysigned policy
tpm2_loadexternal -C o -G rsa -u public.pem -c signing_key.ctx

#
# Test with policy expiration set to zero and no other dependencies
#
## Generate signature with nonceTPM, cpHashA, policyRef and expiration set to 0
echo "00 00 00 00" | xxd -r -p | \
openssl dgst -sha256 -sign private.pem -out signature.dat

tpm2_startauthsession -S session.ctx
tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -L policy.signed
tpm2_flushcontext session.ctx

## Create a sealing object to use the policysigned
echo "plaintext" > secret.dat
tpm2_createprimary -C o -c prim.ctx -Q
tpm2_create -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx \
-C prim.ctx -i secret.dat -L policy.signed -Q

## Satisfy the policy and unseal secret
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -L policy.signed
tpm2_unseal -p session:session.ctx -c sealing_key.ctx -o unsealed.dat
tpm2_flushcontext session.ctx

diff secret.dat unsealed.dat

#
# Test with policy expiration set to zero and policyref/qualifier data
#
## Generate signature with nonceTPM, cpHashA, and expiration set to 0
dd if=/dev/urandom of=qual.dat bs=1 count=32
echo "00 00 00 00" | xxd -r -p | cat - qual.dat | \
openssl dgst -sha256 -sign private.pem -out signature.dat

tpm2_startauthsession -S session.ctx
tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -L policy.signed -q qual.dat
tpm2_flushcontext session.ctx

## Create a sealing object to use the policysigned
echo "plaintext" > secret.dat
tpm2_createprimary -C o -c prim.ctx -Q
tpm2_create -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx \
-C prim.ctx -i secret.dat -L policy.signed -Q

## Satisfy the policy and unseal secret
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -L policy.signed -q qual.dat
tpm2_unseal -p session:session.ctx -c sealing_key.ctx -o unsealed_2.dat
tpm2_flushcontext session.ctx

diff secret.dat unsealed_2.dat

exit 0
