#!/bin/bash
new_path=`pwd`
PATH="$PATH":"$new_path"

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

rm $file_primary_key_ctx $file_signing_key_pub $file_signing_key_priv $file_signing_key_ctx $file_signing_key_name $file_output_data $file_verify_tk_data $file_input_data_hash $file_input_data_hash_tk -rf

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
 echo "no outputfile,sign test Fail!"
 exit 1
fi


#tpm2_verifysignature -c context_load_out_6  -g 0x000B -m secret.data  -s sign.f1 -t tickt_verify_sign.out              
tpm2_verifysignature -c $file_signing_key_ctx  -g $alg_hash -m $file_input_data  -s $file_output_data -t $file_verify_tk_data
if [ $? != 0 ];then
	fail verifysignature   
fi

#./tpm2_hash -H n -g 0x00B -I secret.data -o hash.f.01 -t hash.tk.f.01
tpm2_hash -H n -g $alg_hash -I $file_input_data -o $file_input_data_hash -t $file_input_data_hash_tk

if [ ! -e "$file_input_data_hash" ];then    
 echo "hash $file_input_data Fail!"
 exit 1
fi

rm $file_verify_tk_data -rf
tpm2_verifysignature -c  $file_signing_key_ctx  -D  $file_input_data_hash -s $file_output_data  -t $file_verify_tk_data
if [ $? != 0 ];then
	fail verifysignature   
fi

rm $file_verify_tk_data  $file_signing_key_ctx  -rf
tpm2_loadexternal  -H n -u $file_signing_key_pub -C  $file_signing_key_ctx
if [ ! -e "$file_signing_key_ctx" ];then    
 fail Loadexternal 
fi

###need debug 0x2cb error first ##
tpm2_verifysignature -c  $file_signing_key_ctx  -g $alg_hash -m $file_input_data  -s $file_output_data -t $file_verify_tk_data                         
  if [ $? != 0 ];then
	fail verifysignature 
  fi
