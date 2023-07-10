# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

alg_primary_obj=sha256
alg_primary_key=ecc
alg_create_obj=sha256
pcr_specification=sha256:1,2,3,16+sha1:1,2,3,16
pcr_fwd_specification=sha256:1,2,3,16=bba91ca85dc914b2ec3efb9e16e7267bf9193b14350d20fba8a8b406730ae30a+sha1:1,2,3,16=6fd13bfa9ec8bc42e39d262810bbb912373ca5f9
pcr_sha1_specification=sha1:1,2,3,16
pcr_sha1_fwd_specification=sha1:1,2,3,16=6fd13bfa9ec8bc42e39d262810bbb912373ca5f9
pcr_sha256_specification=sha256:1,2,3,16
pcr_sha256_fwd_specification=sha256:1,2,3,16=bba91ca85dc914b2ec3efb9e16e7267bf9193b14350d20fba8a8b406730ae30a
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
file_auth_session=auth-session.data

secret="12345678"

cleanup() {
  rm -f $file_input_data $file_primary_key_ctx $file_unseal_key_pub \
        $file_unseal_key_priv $file_unseal_key_ctx $file_unseal_key_name \
        $file_unseal_output_data $file_pcr_value $file_policy

  if [ "$1" != "no-shut-down" ]; then
    shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo $secret > $file_input_data

tpm2 clear

tpm2 createprimary -Q -C e -g $alg_primary_obj -G $alg_primary_key \
-c $file_primary_key_ctx

# Test sha1+sha256

resetPCR16

tpm2 startauthsession -Q -S "$file_auth_session"

tpm2 policypcr -Q --session "$file_auth_session" -L "$file_policy" --pcr-list "$pcr_fwd_specification"

tpm2 flushcontext -Q "$file_auth_session"

tpm2 create -g $alg_create_obj -u $file_unseal_key_pub \
-r $file_unseal_key_priv -i- -C $file_primary_key_ctx -L $file_policy \
-a 'fixedtpm|fixedparent' <<< $secret

tpm2 load -C $file_primary_key_ctx -u $file_unseal_key_pub \
-r $file_unseal_key_priv -n $file_unseal_key_name -c $file_unseal_key_ctx

# Test that unseal fails if a PCR policy isn't provided

trap - ERR

# Test that unseal fails if PCR state isn't the same as the defined PCR policy
tpm2 unseal -c $file_unseal_key_ctx -p pcr:$pcr_specification 2> /dev/null
if [ $? != 1 ]; then
  echo "tpm2 unseal didn't fail with a PCR state different than the policy!"
  exit 1
fi

trap onerror ERR

tpm2 pcrextend 16:sha1=6c10289a8da7f774cf67bd2fc8502cd4b585346a
tpm2 pcrextend 16:sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

# Test that the object can be unsealed from forward sealing.

unsealed=`tpm2 unseal -V --object-context $file_unseal_key_ctx \
-p pcr:$pcr_specification`

test "$unsealed" == "$secret"

rm $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_name \
$file_unseal_key_ctx

#Test with sha256 bank
resetPCR16

tpm2 startauthsession -Q -S "$file_auth_session"

tpm2 policypcr -Q --session "$file_auth_session" -L "$file_policy" --pcr-list "$pcr_sha256_fwd_specification"

tpm2 flushcontext -Q "$file_auth_session"

tpm2 create -g $alg_create_obj -u $file_unseal_key_pub \
-r $file_unseal_key_priv -i- -C $file_primary_key_ctx -L $file_policy \
-a 'fixedtpm|fixedparent' <<< $secret

tpm2 load -C $file_primary_key_ctx -u $file_unseal_key_pub \
-r $file_unseal_key_priv -n $file_unseal_key_name -c $file_unseal_key_ctx

# Test that unseal fails if a PCR policy isn't provided

trap - ERR

# Test that unseal fails if PCR state isn't the same as the defined PCR policy
tpm2 unseal -c $file_unseal_key_ctx -p pcr:$pcr_sha256_specification 2> /dev/null
if [ $? != 1 ]; then
  echo "tpm2 unseal didn't fail with a PCR state different than the policy!"
  exit 1
fi

trap onerror ERR

tpm2 pcrextend 16:sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

# Test that the object can be unsealed from forward sealing.

unsealed=`tpm2 unseal -V --object-context $file_unseal_key_ctx \
-p pcr:$pcr_sha256_specification`

test "$unsealed" == "$secret"

rm $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_name \
$file_unseal_key_ctx

#Test with sha1 bank
resetPCR16

tpm2 startauthsession -Q -S "$file_auth_session"

tpm2 policypcr -Q --session "$file_auth_session" -L "$file_policy" --pcr-list "$pcr_sha1_fwd_specification"

tpm2 flushcontext -Q "$file_auth_session"

tpm2 create -g $alg_create_obj -u $file_unseal_key_pub \
-r $file_unseal_key_priv -i- -C $file_primary_key_ctx -L $file_policy \
-a 'fixedtpm|fixedparent' <<< $secret

tpm2 load -C $file_primary_key_ctx -u $file_unseal_key_pub \
-r $file_unseal_key_priv -n $file_unseal_key_name -c $file_unseal_key_ctx

# Test that unseal fails if a PCR policy isn't provided

trap - ERR

# Test that unseal fails if PCR state isn't the same as the defined PCR policy
tpm2 unseal -c $file_unseal_key_ctx -p pcr:$pcr_sha1_specification 2> /dev/null
if [ $? != 1 ]; then
  echo "tpm2 unseal didn't fail with a PCR state different than the policy!"
  exit 1
fi

trap onerror ERR

tpm2 pcrextend 16:sha1=6c10289a8da7f774cf67bd2fc8502cd4b585346a

# Test that the object can be unsealed from forward sealing.

unsealed=`tpm2 unseal -V --object-context $file_unseal_key_ctx \
-p pcr:$pcr_sha1_specification`

test "$unsealed" == "$secret"

rm $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_name \
$file_unseal_key_ctx

exit 0
