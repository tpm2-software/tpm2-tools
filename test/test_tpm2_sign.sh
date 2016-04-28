#!/bin/bash

file_primary_key_ctx=context.p_B1
file_signing_key_pub=opuB1_B8
file_signing_key_priv=oprB1_B8
file_signing_key_ctx=context_load_out_B1_B8
file_signing_key_name=name.load.B1_B8
file_input_data=secret.data
file_output_data=sig.4

  
handle_signing_key=0x81010005

alg_hash=0x000B
alg_primary_key=0x0001
alg_signing_key=0x0008

fail()
{
	    echo "$1 test fail, pelase check the environment or parameters!"
 exit 1
}
Pass()
{
	    echo ""$1" pass" >>test_getpubak_pass.log
}


if [ ! -e "$file_input_data" ]   
  then    
echo "12345678" > $file_input_data
fi 

rm $file_primary_key_ctx $file_signing_key_pub $file_signing_key_priv $file_signing_key_ctx $file_signing_key_name $file_output_data -rf

tpm2_takeownership -c
tpm2_createprimary -A e -g $alg_hash -G $alg_primary_key -C $file_primary_key_ctx
if [ $? != 0 ];then
	 fail createprimary 
fi
tpm2_create -g $alg_hash -G $alg_signing_key -o $file_signing_key_pub -O $file_signing_key_priv  -c $file_primary_key_ctx
if [ $? != 0 ];then
	fail create 
fi
tpm2_load -c $file_primary_key_ctx  -u $file_signing_key_pub  -r $file_signing_key_priv -n $file_signing_key_name -C $file_signing_key_ctx
if [ $? != 0 ];then
	fail load   
fi

tpm2_sign -c $file_signing_key_ctx -g $alg_hash -m $file_input_data -s $file_output_data
if [ ! -e "$file_output_data" ];then    
 fail sign 
else
 rm $file_output_data -rf
fi

tpm2_evictcontrol -A o -c $file_signing_key_ctx -S $handle_signing_key |tee evict.log
c1="$?"
grep "persistentHanlde: "$handle_signing_key"" evict.log
c2="$?"

if [ $c1 != 0 ] || [ $c2 != 0  ];then
     fail evictcontrol 
fi

tpm2_sign -k $handle_signing_key -g $alg_hash -m $file_input_data -s $file_output_data

if [ $? != 0 ];then
    fail sign
fi

