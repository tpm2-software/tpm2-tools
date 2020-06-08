# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f session.ctx secret.dat private.pem public.pem signature.dat \
    signing_key.ctx policy.signed prim.ctx sealing_key.priv sealing_key.pub \
    unsealed.dat qual.dat time.out tic.ket authobj.name to_sign.bin

    tpm2 flushcontext session.ctx 2>/dev/null || true

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

echo "plaintext" > secret.dat

#
# Test with policysigned
#
# Create the signing authority
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
# Load the verification key and Create the policysigned policy
tpm2 loadexternal -C o -G rsa -u public.pem -c signing_key.ctx \
-n signing_key.name

tpm2 startauthsession -S session.ctx
tpm2 policysigned -S session.ctx -c signing_key.ctx -L policy.signed
tpm2 flushcontext session.ctx

# Create a sealing object to use the policysigned
tpm2 createprimary -C o -c prim.ctx -Q
tpm2 create -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx \
-C prim.ctx -i secret.dat -L policy.signed -Q

# Create a policy ticket for policysigned
tpm2 startauthsession -S session.ctx --policy-session

tpm2 policysigned -S session.ctx -c signing_key.ctx -x -t -500 \
--raw-data to_sign.bin
openssl dgst -sha256 -sign private.pem -out signature.dat to_sign.bin

tpm2 policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -x --ticket tic.ket --timeout time.out -t -500

tpm2 flushcontext session.ctx

# Satisfy the policyticket and unseal the secret
tpm2 startauthsession -S session.ctx --policy-session

tpm2 policyticket -S session.ctx -n signing_key.name --ticket tic.ket \
--timeout time.out

tpm2 unseal -p session:session.ctx -c sealing_key.ctx -o unsealed.dat

tpm2 flushcontext session.ctx

diff secret.dat unsealed.dat

rm -f unsealed.dat

#
# Test with policysecret
#
tpm2 clear

tpm2 startauthsession -S session.ctx
tpm2 policysecret -S session.ctx -c o -L policy.secret
tpm2 flushcontext session.ctx

tpm2 createprimary -C o -c prim.ctx -Q
tpm2 create -Q -g sha256 -u sealing_key.pub -r sealing_key.priv -C prim.ctx \
-L policy.secret -i secret.dat
tpm2 load -C prim.ctx -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx

tpm2 startauthsession -S session.ctx --policy-session
tpm2 policysecret -S session.ctx -c o -t -500 --timeout time.out \
--ticket tic.ket --nonce-tpm
tpm2 flushcontext session.ctx

TPM2_RH_OWNER="40000001"
echo $TPM2_RH_OWNER | xxd -r -p > authobj.name
tpm2 startauthsession -S session.ctx --policy-session
tpm2 policyticket -S session.ctx -n authobj.name --ticket tic.ket \
--timeout time.out
tpm2 unseal -p"session:session.ctx" -c sealing_key.ctx -o unsealed.dat
tpm2 flushcontext session.ctx

diff secret.dat unsealed.dat

exit 0
