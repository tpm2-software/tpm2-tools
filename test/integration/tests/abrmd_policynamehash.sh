# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f helpers.sh signing_key_private.pem signing_key_public.pem \
    signing_key.ctx signing_key.name authorized.policy policy.dat \
    primary.ctx key.prv key.pub key.ctx new_parent.prv new_parent.pub \
    new_parent.ctx new_parent.name key.name name.hash policy.namehash \
    policynamehash.signature policy.namehash verification.tkt dupprv.bin \
    dupseed.dat

    tpm2 flushcontext session.ctx 2>/dev/null || true
    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

#
# Restrict key duplication to specific new parent and specific duplicable key.
#

# Generate a duplicable object


openssl genrsa -out signing_key_private.pem 2048

openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout

tpm2 loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx \
-n signing_key.name

tpm2 startauthsession -S session.ctx -g sha256

tpm2 policyauthorize -S session.ctx -L authorized.policy -n signing_key.name

tpm2 policycommandcode -S session.ctx -L policy.dat TPM2_CC_Duplicate

tpm2 flushcontext session.ctx

tpm2 createprimary -C o -g sha256 -G rsa -c primary.ctx -Q

## The duplicable key
tpm2 create -Q -C primary.ctx -g sha256 -G rsa -r key.prv -u key.pub \
-L policy.dat -a "sensitivedataorigin|sign|decrypt"

tpm2 load -Q -C primary.ctx -r key.prv -u key.pub -c key.ctx


# Create the new parent


tpm2 create -Q -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
-u new_parent.pub \
-a "decrypt|fixedparent|fixedtpm|restricted|sensitivedataorigin"

tpm2 loadexternal -Q -C o -u new_parent.pub -c new_parent.ctx


# Modify the duplicable key policy to namehash policy to restrict parent and key

tpm2 readpublic -Q -c new_parent.ctx -n new_parent.name

tpm2 readpublic -Q -c key.ctx -n key.name

cat key.name new_parent.name | openssl dgst -sha256 -binary > name.hash

tpm2 startauthsession -S session.ctx -g sha256

tpm2 policynamehash -L policy.namehash -S session.ctx -n name.hash

tpm2 flushcontext session.ctx

openssl dgst -sha256 -sign signing_key_private.pem \
-out policynamehash.signature policy.namehash

tpm2 startauthsession -S session.ctx -g sha256

tpm2 policyauthorize -S session.ctx -L authorized.policy -i policy.namehash \
-n signing_key.name

tpm2 policycommandcode -S session.ctx -L policy.dat TPM2_CC_Duplicate

tpm2 flushcontext session.ctx


# Satisfy the policy and attempt key duplication

tpm2 verifysignature -c signing_key.ctx -g sha256 -m policy.namehash \
-s policynamehash.signature -t verification.tkt -f rsassa

tpm2 startauthsession -S session.ctx --policy-session -g sha256

tpm2 policynamehash -S session.ctx -n name.hash

tpm2 policyauthorize -S session.ctx -i policy.namehash -n signing_key.name \
-t verification.tkt

tpm2 policycommandcode -S session.ctx TPM2_CC_Duplicate

tpm2 duplicate -C new_parent.ctx -c key.ctx -G null -p "session:session.ctx" \
-r dupprv.bin -s dupseed.dat

tpm2 flushcontext session.ctx

# Attempt duplicating the key to a parent that is not in the policynamehash

tpm2 create -Q -C primary.ctx -g sha256 -G rsa -r unintended_parent.prv \
-u unintended_parent.pub \
-a "decrypt|fixedparent|fixedtpm|restricted|sensitivedataorigin"

tpm2 loadexternal -Q -C o -u unintended_parent.pub -c unintended_parent.ctx

tpm2 startauthsession -S session.ctx --policy-session -g sha256

tpm2 policynamehash -S session.ctx -n name.hash

tpm2 policyauthorize -S session.ctx -i policy.namehash -n signing_key.name \
-t verification.tkt

tpm2 policycommandcode -S session.ctx TPM2_CC_Duplicate

trap - ERR

tpm2 duplicate -C unintended_parent.ctx -c key.ctx -G null \
-p "session:session.ctx" -r dupprv.bin -s dupseed.dat
if [ $? == 0 ];then
  echo "ERROR: Duplication had to fail!"
  exit 1
fi

trap onerror ERR

tpm2 flushcontext session.ctx

exit 0
