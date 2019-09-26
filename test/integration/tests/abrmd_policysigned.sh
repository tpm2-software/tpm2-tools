# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f session.ctx secret.dat private.pem public.pem signature.dat \
    signing_key.ctx policy.signed prim.ctx sealing_key.priv sealing_key.pub \
    unsealed.dat

    tpm2_flushcontext $session_ctx 2>/dev/null || true

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

## Create the signing authority
openssl genrsa -out private.pem 2048

openssl rsa -in private.pem -outform PEM -pubout -out public.pem

## Generate signature with nonceTPM, cpHashA, policyRef and expiration set to 0
echo "00 00 00 00" | xxd -r -p | \
openssl dgst -sha256 -sign private.pem -out signature.dat

## Load the verification key and Create the policysigned policy
tpm2_loadexternal -C o -G rsa -u public.pem -c signing_key.ctx

tpm2_startauthsession -S session.ctx

tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -L policy.signed

tpm2_flushcontext session.ctx

## Create a sealing object to use the policysigned
echo "plaintext" > secret.dat

tpm2_createprimary -C o -c prim.ctx

tpm2_create -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx \
-C prim.ctx -i secret.dat -L policy.signed

## Satisfy the policy and unseal secret
tpm2_startauthsession -S session.ctx --policy-session

tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -L policy.signed

tpm2_unseal -p session:session.ctx -c sealing_key.ctx -o unsealed.dat

tpm2_flushcontext session.ctx

diff secret.dat unsealed.dat

exit 0
