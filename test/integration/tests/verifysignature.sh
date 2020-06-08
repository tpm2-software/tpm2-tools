# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

file_primary_key_ctx=context.p_B1
file_signing_key_pub=opuB1_B8
file_signing_key_priv=oprB1_B8
file_signing_key_ctx=context_load_out_B1_B8
file_signing_key_name=name.load.B1_B8
file_input_data=secret.data
file_output_data=sig.4
file_verify_tk_data=tickt_verify_sig.4

file_input_data_hash=secret_hash.data
file_input_data_hash_tk=secret_hash_tk.data

handle_signing_key=0x81010005

alg_hash=sha256
alg_primary_key=rsa
alg_signing_key=rsa

cleanup() {
    rm -f $file_primary_key_ctx $file_signing_key_pub $file_signing_key_priv \
          $file_signing_key_ctx $file_signing_key_name $file_output_data \
          $file_verify_tk_data $file_input_data_hash $file_input_data_hash_tk \
          $file_input_data

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo "12345678" > $file_input_data

tpm2 clear

tpm2 createprimary -Q -C e -g $alg_hash -G $alg_primary_key \
-c $file_primary_key_ctx

tpm2 create -Q -g $alg_hash -G $alg_signing_key -u $file_signing_key_pub \
-r $file_signing_key_priv -C $file_primary_key_ctx

tpm2 load -Q -C $file_primary_key_ctx -u $file_signing_key_pub \
-r $file_signing_key_priv -n $file_signing_key_name -c $file_signing_key_ctx

tpm2 sign -Q -c $file_signing_key_ctx -g $alg_hash -o $file_output_data \
$file_input_data

tpm2 verifysignature -Q -c $file_signing_key_ctx -g $alg_hash \
-m $file_input_data -s $file_output_data -t $file_verify_tk_data

tpm2 hash -Q -C n -g $alg_hash -o $file_input_data_hash \
-t $file_input_data_hash_tk $file_input_data

rm -f $file_verify_tk_data
tpm2 verifysignature -Q -c $file_signing_key_ctx -d $file_input_data_hash \
-s $file_output_data -t $file_verify_tk_data

rm -f $file_verify_tk_data $file_signing_key_ctx -rf
tpm2 loadexternal -Q -C n -u $file_signing_key_pub -c $file_signing_key_ctx

tpm2 verifysignature -Q -c $file_signing_key_ctx -g $alg_hash \
-m $file_input_data -s $file_output_data -t $file_verify_tk_data

exit 0
