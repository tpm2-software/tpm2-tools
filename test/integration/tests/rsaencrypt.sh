# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

file_primary_key_ctx=context.p_B1
file_rsaencrypt_key_pub=opuB1_B8
file_rsaencrypt_key_priv=oprB1_B8
file_rsaencrypt_key_ctx=context_load_out_B1_B8
file_rsaencrypt_key_name=name.load.B1_B8

file_rsa_en_output_data=rsa_en.out
file_input_data=secret.data

alg_hash=sha256
alg_primary_key=rsa
alg_rsaencrypt_key=rsa

cleanup() {
    rm -f $file_input_data $file_primary_key_ctx $file_rsaencrypt_key_pub \
          $file_rsaencrypt_key_priv $file_rsaencrypt_key_ctx \
          $file_rsaencrypt_key_name $file_rsa_en_output_data

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo "12345678" > $file_input_data

tpm2_clear

tpm2_createprimary -Q -C e -g $alg_hash -G $alg_primary_key \
-c $file_primary_key_ctx

tpm2_create -Q -g $alg_hash -G $alg_rsaencrypt_key -u $file_rsaencrypt_key_pub \
-r $file_rsaencrypt_key_priv -C $file_primary_key_ctx

tpm2_loadexternal -Q -C n   -u $file_rsaencrypt_key_pub \
-c $file_rsaencrypt_key_ctx

#./tpm2_rsaencrypt -c context_loadexternal_out6.out -I secret.data -o rsa_en.out
tpm2_rsaencrypt -Q -c $file_rsaencrypt_key_ctx -o $file_rsa_en_output_data \
$file_input_data

# Test stdout output and test that stdin pipe works as well.
cat $file_input_data | tpm2_rsaencrypt -c $file_rsaencrypt_key_ctx > /dev/null

exit 0
