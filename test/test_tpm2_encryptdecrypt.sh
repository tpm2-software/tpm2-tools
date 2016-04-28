#!/bin/bash
new_path=`pwd`
PATH="$PATH":"$new_path"

alg_primary_obj=0x0004
alg_primary_key=0x0001
alg_create_obj=0x000B
alg_create_key=0x0025

file_input_data=secret.data
file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_en_decrypt_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_en_decrypt_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_en_decrypt_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_en_decrypt_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_encrypt_output_data=encrypt_"$file_en_decrypt_key_ctx"
file_decrypt_output_data=decrypt_"$file_en_decrypt_key_ctx"

fail()
{
	    echo "$1 test fail, pelase check the environment or parameters!"
 exit 1
}
Pass()
{
	    echo ""$1" pass" >>test_getpubak_pass.log
}

rm $file_primary_key_ctx $file_en_decrypt_key_pub $file_en_decrypt_key_priv $file_en_decrypt_key_name $file_en_decrypt_key_ctx  $file_encrypt_output_data $file_decrypt_output_data -rf


if [ ! -e "$file_input_data" ]   
  then    
echo "12345678" > $file_input_data
fi 

tpm2_takeownership -c

tpm2_createprimary -A e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx
if [ $? != 0 ];then
	 fail createprimary 
fi
tpm2_create -g $alg_create_obj -G $alg_create_key -o $file_en_decrypt_key_pub -O $file_en_decrypt_key_priv  -c $file_primary_key_ctx
if [ $? != 0 ];then
	fail create 
fi

tpm2_load -c $file_primary_key_ctx  -u $file_en_decrypt_key_pub  -r $file_en_decrypt_key_priv -n $file_en_decrypt_key_name -C $file_en_decrypt_key_ctx
if [ $? != 0 ];then
	fail load   
fi

tpm2_encryptdecrypt -c $file_en_decrypt_key_ctx  -D NO -I secret.data -o $file_encrypt_output_data
if [ $? != 0 ];then
	fail decrypt 
fi
tpm2_encryptdecrypt -c  $file_en_decrypt_key_ctx -D YES -I $file_encrypt_output_data -o $file_decrypt_output_data
if [ $? != 0 ];then
	fail decrypt 
fi

echo "encryptdecrypt test OK!"

