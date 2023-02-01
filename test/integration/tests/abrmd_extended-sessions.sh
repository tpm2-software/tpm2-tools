# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

alg_primary_obj=sha256
alg_primary_key=ecc
alg_create_obj=sha256
alg_pcr_policy=sha1

pcr_ids=0,1,2,3

file_pcr_value=pcr.bin
file_input_data=secret.data
file_policy=policy.data
file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_unseal_key_pub=opu_"$alg_create_obj"
file_unseal_key_priv=opr_"$alg_create_obj"
file_unseal_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-\
"$alg_create_obj"
file_unseal_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-\
"$alg_create_obj"
file_unseal_output_data=usl_"$file_unseal_key_ctx"
file_session_file=session.dat

secret=12345678

cleanup() {
    rm -f $file_input_data $file_primary_key_ctx $file_unseal_key_pub \
        $file_unseal_key_priv $file_unseal_key_ctx $file_unseal_key_name \
        $file_unseal_output_data $file_pcr_value \
        $file_policy $file_session_file

    tpm2 flushcontext $file_session_file 2>/dev/null || true

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

echo $secret > $file_input_data

tpm2 clear

#
# Test an extended policy session beyond client connections. This is ONLY
# supported by abrmd since version: https://github.com/tpm2-software/tpm2-abrmd/
# releases/tag/1.2.0 However, bug: https://github.com/tpm2-software/tpm2-abrmd/
# issues/285 applies.
#
# The test works by:
# Step 1: Creating a trial session and updating it with a policyPCR event to
# generate a policy hash.
#
# Step 2: Creating an object and using that policy hash as the policy to satisfy
# for usage.
#
# Step 3: Creating an actual policy session and using pcrpolicy event to update
# the policy.
#
# Step 4: Using that actual policy session from step 3 in tpm2 unseal to unseal
# the object.
#

tpm2 createprimary -Q -C e -g $alg_primary_obj -G $alg_primary_key \
-c $file_primary_key_ctx

tpm2 pcrread -Q -o $file_pcr_value ${alg_pcr_policy}:${pcr_ids}

tpm2 startauthsession -Q -S $file_session_file

tpm2 policypcr -Q -S $file_session_file -l ${alg_pcr_policy}:${pcr_ids} \
-f $file_pcr_value -L $file_policy

tpm2 flushcontext $file_session_file

tpm2 create -Q -g $alg_create_obj -u $file_unseal_key_pub \
-r $file_unseal_key_priv -i- -C $file_primary_key_ctx -L $file_policy \
-a 'fixedtpm|fixedparent' <<< $secret

tpm2 load -Q -C $file_primary_key_ctx -u $file_unseal_key_pub \
-r $file_unseal_key_priv -n $file_unseal_key_name -c $file_unseal_key_ctx

rm $file_session_file

# Start a REAL encrypted and bound policy session (-a option) and perform a pcr
# policy event
tpm2 startauthsession --policy-session -c $file_primary_key_ctx \
-S $file_session_file

tpm2 policypcr -Q -S $file_session_file -l ${alg_pcr_policy}:${pcr_ids} \
-f $file_pcr_value -L $file_policy

unsealed=`tpm2 unseal -p"session:$file_session_file" -c $file_unseal_key_ctx`

test "$unsealed" == "$secret"

# Test resetting the policy session causes unseal to fail.
tpm2 policyrestart -S $file_session_file

# negative test, clear the error handler
if tpm2 unseal -p"session:$file_session_file" \
-c $file_unseal_key_ctx 2>/dev/null; then
    echo "Expected tpm2 unseal to fail after policy reset"
    exit 1
else
    true
fi

# Test bounded sessions work with bind entities with auth
tpm2 createprimary -Q -C o -c prim.ctx -p primepass
## Test with bounded and salted session
tpm2 startauthsession -S session.ctx --hmac-session --tpmkey-context prim.ctx \
--bind-context prim.ctx --bind-auth primepass
tpm2 sessionconfig session.ctx --enable-encrypt --enable-decrypt
tpm2 getrandom 8 -S session.ctx
tpm2 flushcontext session.ctx
## Test with bounded only session
tpm2 startauthsession -S session.ctx --hmac-session \
--bind-context prim.ctx  --bind-auth primepass
tpm2 sessionconfig session.ctx --enable-encrypt --enable-decrypt
tpm2 getrandom 8 -S session.ctx
tpm2 flushcontext session.ctx
## Test with bounded only session (with file attribute)
tpm2 startauthsession -S session.ctx --hmac-session \
--bind-context prim.ctx  --bind-auth file:-<<EOF
primepass
EOF
tpm2 sessionconfig session.ctx --enable-encrypt --enable-decrypt
tpm2 getrandom 8 -S session.ctx
tpm2 flushcontext session.ctx
## Test with salted only session
tpm2 startauthsession -S session.ctx --hmac-session \
--tpmkey-context prim.ctx
tpm2 sessionconfig session.ctx --enable-encrypt --enable-decrypt
tpm2 getrandom 8 -S session.ctx
tpm2 flushcontext session.ctx

# test that name verification works
tpm2 evictcontrol -c prim.ctx 0x81000000
tpm2 readpublic -c prim.ctx -n name.bin
tpm2 startauthsession -S session.ctx --policy-session \
  --tpmkey-context 0x81000000 -n name.bin
# verify -c works
tpm2 startauthsession -S session.ctx --policy-session \
  -c 0x81000000 -n name.bin

# test if name is bad, generate a random name of of the same size
# Note FreeBSD stat has no printf and wc prints spaces hence the sed.
size=$(wc -c < name.bin | sed 's/ //g')
dd if=/dev/urandom bs=${size} count=1 of=name2.bin

if tpm2 startauthsession -S session.ctx --policy-session \
  --tpmkey-context 0x81000000 -n name2.bin 2>/dev/null; then
    echo "Expected tpm2 startauthsession to fail with bad name"
    exit 1
else
    true
fi

if tpm2 startauthsession -S session.ctx --policy-session \
  -c 0x81000000 -n name2.bin 2>/dev/null; then
    echo "Expected tpm2 startauthsession to fail with bad name"
    exit 1
else
    true
fi

exit 0
