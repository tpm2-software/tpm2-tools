#!/bin/bash
new_path=`pwd`
PATH="$PATH":"$new_path"

file_primary_key_ctx=context.p_B1
file_certify_key_pub=opuB1_B8
file_certify_key_priv=oprB1_B8
file_certify_key_ctx=context_load_out_B1_B8
file_certify_key_name=name.load.B1_B8
file_output_data=
file_verify_output_data= 
  

alg_hash=0x000B
alg_primary_key=0x0001
alg_certify_key=0x0001


rm $file_primary_key_ctx $file_certify_key_pub $file_certify_key_priv $file_certify_key_ctx $file_certify_key_name $file_output_data -rf

tpm2_takeownership -c
tpm2_createprimary -A e -g $alg_hash -G $alg_primary_key -C $file_primary_key_ctx
if [ $? != 0 ];then
echo "createprimary fail, pelase check the environment or parameters!"
exit 1
fi
tpm2_create -g $alg_hash -G $alg_certify_key -o $file_certify_key_pub -O $file_certify_key_priv  -c $file_primary_key_ctx
if [ $? != 0 ];then
echo "create fail, pelase check the environment or parameters!"
exit 1
fi
tpm2_load -c $file_primary_key_ctx  -u $file_certify_key_pub  -r $file_certify_key_priv -n $file_certify_key_name -C $file_certify_key_ctx
if [ $? != 0 ];then
echo "load fail, pelase check the environment or parameters!"
exit 1
fi
tpm2_certify -C $file_primary_key_ctx  -c $file_certify_key_ctx -g $alg_hash -a attest.out -s certify_signature.out
if [ $? != 0 ];then
 echo "certify fail, pelase check the environment or parameters!"
 exit 1
fi


