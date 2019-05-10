#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

alg_primary_obj=sha256
alg_primary_key=ecc
alg_create_obj=sha256
alg_pcr_policy=sha1

pcr_ids="0,1,2,3"

file_pcr_value=pcr.bin
file_input_data=secret.data
file_policy=policy.data
file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_unseal_key_pub=opu_"$alg_create_obj"
file_unseal_key_priv=opr_"$alg_create_obj"
file_unseal_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"
file_unseal_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"
file_unseal_output_data=usl_"$file_unseal_key_ctx"

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

tpm2_clear

tpm2_createprimary -Q -a e -g $alg_primary_obj -G $alg_primary_key -o $file_primary_key_ctx

tpm2_create -Q -g $alg_create_obj -u $file_unseal_key_pub -r $file_unseal_key_priv -i $file_input_data -C $file_primary_key_ctx

tpm2_load -Q -C $file_primary_key_ctx  -u $file_unseal_key_pub  -r $file_unseal_key_priv -n $file_unseal_key_name -o $file_unseal_key_ctx

tpm2_unseal -Q -c $file_unseal_key_ctx -o $file_unseal_output_data

cmp -s $file_unseal_output_data $file_input_data

# Test -i using stdin via pipe

rm $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_name $file_unseal_key_ctx

cat $file_input_data | tpm2_create -Q -g $alg_create_obj -u $file_unseal_key_pub -r $file_unseal_key_priv -i- -C $file_primary_key_ctx

tpm2_load -Q -C $file_primary_key_ctx  -u $file_unseal_key_pub  -r $file_unseal_key_priv -n $file_unseal_key_name -o $file_unseal_key_ctx

tpm2_unseal -Q -c $file_unseal_key_ctx -o $file_unseal_output_data

cmp -s $file_unseal_output_data $file_input_data

# Test using a PCR policy for auth and use file based stdin for -i

rm $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_name $file_unseal_key_ctx

tpm2_pcrlist -Q -L ${alg_pcr_policy}:${pcr_ids} -o $file_pcr_value

tpm2_createpolicy -Q --policy-pcr -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value -o $file_policy

tpm2_create -Q -g $alg_create_obj -u $file_unseal_key_pub -r $file_unseal_key_priv -i- -C $file_primary_key_ctx -L $file_policy \
  -b 'fixedtpm|fixedparent' <<< $secret

tpm2_load -Q -C $file_primary_key_ctx  -u $file_unseal_key_pub  -r $file_unseal_key_priv -n $file_unseal_key_name -o $file_unseal_key_ctx

unsealed=`tpm2_unseal -V --context-object $file_unseal_key_ctx -p pcr:${alg_pcr_policy}:${pcr_ids}+$file_pcr_value`

test "$unsealed" == "$secret"

# Test that unseal fails if a PCR policy isn't provided

trap - ERR

tpm2_unseal -c $file_unseal_key_ctx 2> /dev/null
if [ $? != 1 ]; then
  echo "tpm2_unseal didn't fail without a PCR policy!"
  exit 1
fi

# Test that unseal fails if PCR state isn't the same as the defined PCR policy

pcr_extend=$(echo $pcr_ids | cut -d ',' -f1)

tpm2_pcrextend $pcr_extend:sha1=6c10289a8da7f774cf67bd2fc8502cd4b585346a

tpm2_unseal -c $file_unseal_key_ctx -p pcr:${alg_pcr_policy}:${pcr_ids} 2> /dev/null
if [ $? != 1 ]; then
  echo "tpm2_unseal didn't fail with a PCR state different than the policy!"
  exit 1
fi

# Test that the object can be unsealed without a policy but a password

trap onerror ERR

rm $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_name $file_unseal_key_ctx

tpm2_pcrlist -Q -L ${alg_pcr_policy}:${pcr_ids} -o $file_pcr_value

tpm2_createpolicy -Q --policy-pcr -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value -o $file_policy

tpm2_create -Q -g $alg_create_obj -u $file_unseal_key_pub -r $file_unseal_key_priv -i- -C $file_primary_key_ctx -L $file_policy -p secretpass <<< $secret

tpm2_load -Q -C $file_primary_key_ctx  -u $file_unseal_key_pub  -r $file_unseal_key_priv -n $file_unseal_key_name -o $file_unseal_key_ctx

unsealed=`tpm2_unseal -c $file_unseal_key_ctx -p secretpass`

test "$unsealed" == "$secret"

# Test that unseal fails when using a wrong password

trap - ERR

tpm2_unseal -c $file_unseal_key_ctx -p wrongpass 2> /dev/null
if [ $? != 1 ]; then
  echo "tpm2_unseal didn't fail when using a wrong object password!"
  exit 1
fi

exit 0
