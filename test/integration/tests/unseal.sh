# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

alg_primary_obj=sha256
alg_primary_key=ecc
alg_create_obj=sha256
pcr_specification=sha256:0,1,2,3+sha1:0,1,2,3
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

tpm2 create -Q -g $alg_create_obj -u $file_unseal_key_pub \
-r $file_unseal_key_priv -i $file_input_data -C $file_primary_key_ctx

tpm2 load -Q -C $file_primary_key_ctx -u $file_unseal_key_pub \
-r $file_unseal_key_priv -n $file_unseal_key_name -c $file_unseal_key_ctx

tpm2 unseal -Q -c $file_unseal_key_ctx -o $file_unseal_output_data

cmp -s $file_unseal_output_data $file_input_data

# Test -i using stdin via pipe

rm $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_name \
$file_unseal_key_ctx

cat $file_input_data | tpm2 create -Q -g $alg_create_obj \
-u $file_unseal_key_pub -r $file_unseal_key_priv -i- -C $file_primary_key_ctx

tpm2 load -Q -C $file_primary_key_ctx -u $file_unseal_key_pub \
-r $file_unseal_key_priv -n $file_unseal_key_name -c $file_unseal_key_ctx

tpm2 unseal -Q -c $file_unseal_key_ctx -o $file_unseal_output_data

cmp -s $file_unseal_output_data $file_input_data

# Test using a PCR policy for auth and use file based stdin for -i

rm $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_name \
$file_unseal_key_ctx

tpm2 pcrread -Q -o $file_pcr_value $pcr_specification

tpm2 createpolicy -Q --policy-pcr -l $pcr_specification -f $file_pcr_value \
-L $file_policy

tpm2 create -Q -g $alg_create_obj -u $file_unseal_key_pub \
-r $file_unseal_key_priv -i- -C $file_primary_key_ctx -L $file_policy \
-a 'fixedtpm|fixedparent' <<< $secret

tpm2 load -Q -C $file_primary_key_ctx -u $file_unseal_key_pub \
-r $file_unseal_key_priv -n $file_unseal_key_name -c $file_unseal_key_ctx

unsealed=`tpm2 unseal -V --object-context $file_unseal_key_ctx \
-p pcr:$pcr_specification=$file_pcr_value`

test "$unsealed" == "$secret"

# Test that unseal fails if a PCR policy isn't provided

trap - ERR

tpm2 unseal -c $file_unseal_key_ctx 2> /dev/null
if [ $? != 1 ]; then
  echo "tpm2 unseal didn't fail without a PCR policy!"
  exit 1
fi

# Test that unseal fails if PCR state isn't the same as the defined PCR policy

tpm2 pcrextend 0:sha1=6c10289a8da7f774cf67bd2fc8502cd4b585346a

tpm2 unseal -c $file_unseal_key_ctx -p pcr:$pcr_specification 2> /dev/null
if [ $? != 1 ]; then
  echo "tpm2 unseal didn't fail with a PCR state different than the policy!"
  exit 1
fi

# Test that the object can be unsealed without a policy but a password

trap onerror ERR

rm $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_name \
$file_unseal_key_ctx

tpm2 pcrread -Q -o $file_pcr_value $pcr_specification

tpm2 createpolicy -Q --policy-pcr -l $pcr_specification -f $file_pcr_value \
-L $file_policy

tpm2 create -Q -g $alg_create_obj -u $file_unseal_key_pub \
-r $file_unseal_key_priv -i- -C $file_primary_key_ctx -L $file_policy \
-p secretpass <<< $secret

tpm2 load -Q -C $file_primary_key_ctx -u $file_unseal_key_pub \
-r $file_unseal_key_priv -n $file_unseal_key_name -c $file_unseal_key_ctx

unsealed=`tpm2 unseal -c $file_unseal_key_ctx -p secretpass`

test "$unsealed" == "$secret"

# Test that unseal fails when using a wrong password

trap - ERR

tpm2 unseal -c $file_unseal_key_ctx -p wrongpass 2> /dev/null
if [ $? != 3 ]; then
  echo "tpm2 unseal didn't fail when using a wrong object password!"
  exit 1
fi

# Test unsealing with encrypted sessions
trap onerror ERR

tpm2 createprimary -Q -C o -c prim.ctx
tpm2 startauthsession -S enc_session.ctx --hmac-session -c prim.ctx
tpm2 sessionconfig enc_session.ctx --disable-encrypt

tpm2 create -Q -C prim.ctx -u seal_key.pub -r seal_key.priv -c seal_key.ctx \
-p sealkeypass -i- <<< $secret -S enc_session.ctx

tpm2 sessionconfig enc_session.ctx --enable-encrypt --disable-continuesession
unsealed=`tpm2 unseal -c seal_key.ctx -p sealkeypass -S enc_session.ctx`
test "$unsealed" == "$secret"

exit 0
