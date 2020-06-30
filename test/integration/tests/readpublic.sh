# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

alg_primary_obj=sha256
alg_primary_key=rsa
alg_create_obj=sha256
alg_create_key=hmac

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_readpub_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_readpub_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_readpub_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-\
"$alg_create_obj"_"$alg_create_key"
file_readpub_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-\
"$alg_create_obj"_"$alg_create_key"
file_readpub_output=readpub_"$file_readpub_key_ctx"

Handle_readpub=0x81010014

cleanup() {
    rm -f $file_primary_key_ctx $file_readpub_key_pub $file_readpub_key_priv \
    $file_readpub_key_name $file_readpub_key_ctx $file_readpub_output

    tpm2 evictcontrol -Q -C o -c $Handle_readpub 2>/dev/null || true

    if [ "$1" != "no-shut-down" ]; then
       shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear

tpm2 createprimary -Q -C e -g $alg_primary_obj -G $alg_primary_key \
-c $file_primary_key_ctx

tpm2 create -Q -g $alg_create_obj -G $alg_create_key -u $file_readpub_key_pub \
-r $file_readpub_key_priv -C $file_primary_key_ctx

tpm2 load -Q -C $file_primary_key_ctx -u $file_readpub_key_pub \
-r $file_readpub_key_priv -n $file_readpub_key_name -c $file_readpub_key_ctx

tpm2 readpublic -Q -c $file_readpub_key_ctx -o $file_readpub_output

tpm2 evictcontrol -Q -C o -c $file_readpub_key_ctx $Handle_readpub

rm -f $file_readpub_output
tpm2 readpublic -Q -c $Handle_readpub -o $file_readpub_output

exit 0
