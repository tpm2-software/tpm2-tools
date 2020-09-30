# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f session.ctx secret.dat private.pem public.pem signature.dat \
    signing_key.ctx policy.signed prim.ctx sealing_key.priv sealing_key.pub \
    unsealed.dat qual.dat to_sign.bin

    tpm2 flushcontext $session_ctx 2>/dev/null || true

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

echo "plaintext" > secret.dat

# Create the signing authority
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
# Load the verification key and Create the policysigned policy
tpm2 loadexternal -C o -G rsa -u public.pem -c signing_key.ctx

#
# Test with policy expiration set to zero and no other dependencies
#
tpm2 startauthsession -S session.ctx
tpm2 policysigned -S session.ctx -c signing_key.ctx -L policy.signed
tpm2 flushcontext session.ctx

## Create a sealing object to use the policysigned
tpm2 createprimary -C o -c prim.ctx -Q
tpm2 create -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx \
-C prim.ctx -i secret.dat -L policy.signed -Q

## Unseal secret
tpm2 startauthsession -S session.ctx --policy-session
### Generate signature with nonceTPM, cpHashA, policyRef and expiration set to 0
tpm2 policysigned -S session.ctx -c signing_key.ctx --raw-data to_sign.bin
openssl dgst -sha256 -sign private.pem -out signature.dat to_sign.bin
### Satisfy policy
tpm2 policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx
### Unseal
tpm2 unseal -p session:session.ctx -c sealing_key.ctx -o unsealed.dat
tpm2 flushcontext session.ctx
diff secret.dat unsealed.dat
rm -f unsealed.dat

#
# Test with policy expiration set to zero and policyref/qualifier data
#
dd if=/dev/urandom of=qual.dat bs=1 count=32 status=none
tpm2 startauthsession -S session.ctx
tpm2 policysigned -S session.ctx -c signing_key.ctx -L policy.signed -q qual.dat
tpm2 flushcontext session.ctx

## Create a sealing object to use the policysigned
tpm2 createprimary -C o -c prim.ctx -Q
tpm2 create -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx \
-C prim.ctx -i secret.dat -L policy.signed -Q

## Unseal secret
tpm2 startauthsession -S session.ctx --policy-session
### Generate signature with nonceTPM, cpHashA, and expiration set to 0
tpm2 policysigned -S session.ctx -c signing_key.ctx -q qual.dat \
--raw-data to_sign.bin
openssl dgst -sha256 -sign private.pem -out signature.dat to_sign.bin
### Satisfy policy
tpm2 policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -q qual.dat
tpm2 unseal -p session:session.ctx -c sealing_key.ctx -o unsealed.dat
tpm2 flushcontext session.ctx
diff secret.dat unsealed.dat
rm -f unsealed.dat

#
# Test with nonceTPM
#
tpm2 startauthsession -S session.ctx
tpm2 policysigned -S session.ctx -c signing_key.ctx -L policy.signed
tpm2 flushcontext session.ctx
tpm2 createprimary -C o -c prim.ctx -Q
tpm2 create -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx \
-C prim.ctx -i secret.dat -L policy.signed -Q
## Unseal secret
tpm2 startauthsession -S session.ctx --policy-session --nonce-tpm nonce_tpm.bin
### Generate signature
tpm2 policysigned -S session.ctx -c signing_key.ctx -x --raw-data to_sign.bin
cmp -n32 nonce_tpm.bin to_sign.bin
openssl dgst -sha256 -sign private.pem -out signature.dat to_sign.bin
###Satisfy the policy
tpm2 policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -x
tpm2 unseal -p session:session.ctx -c sealing_key.ctx -o unsealed.dat
tpm2 flushcontext session.ctx
diff secret.dat unsealed.dat
rm -f unsealed.dat

exit 0
