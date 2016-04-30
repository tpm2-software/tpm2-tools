#!/bin/bash
new_path=`pwd`
PATH="$PATH":"$new_path"

alg_primary_obj=0x000B
alg_primary_key=0x0001
alg_create_obj=0x000B
alg_create_key=0x0008

alg_load=0x0004

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_load_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_load_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_load_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_load_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_load_output=load_"$file_load_key_ctx"

Handle_parent=0x81010018
Handle_ek_load=0x81010017

fail()
{
	    echo "$1 test fail, pelase check the environment or parameters!"
#			    echo ""$1" fail" >>test_encryptdecrypt_error.log
 exit 1
}
Pass()
{
	    echo ""$1" pass" >>test_getpubak_pass.log
}

rm $file_primary_key_ctx $file_load_key_pub $file_load_key_priv $file_load_key_name $file_load_key_ctx  $file_load_output  -rf


tpm2_takeownership -c

tpm2_createprimary -A e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx
if [ $? != 0 ];then
	 fail createprimary 
fi
tpm2_create -g $alg_create_obj -G $alg_create_key -o $file_load_key_pub -O $file_load_key_priv  -c $file_primary_key_ctx
if [ $? != 0 ];then
	fail create 
fi

tpm2_load -c $file_primary_key_ctx  -u $file_load_key_pub  -r $file_load_key_priv -n $file_load_key_name -C $file_load_key_ctx
if [ $? != 0 ];then
	fail load   
fi

#####handle test

rm  $file_load_key_pub $file_load_key_priv $file_load_key_name $file_load_key_ctx  $file_load_output  -rf
tpm2_evictcontrol -A o -c $file_primary_key_ctx  -S $Handle_parent
if [ $? != 0 ];then
	fail evict   
fi
tpm2_create  -H $Handle_parent   -g $alg_create_obj  -G $alg_create_key -o $file_load_key_pub  -O  $file_load_key_priv  
if [ $? != 0 ];then
	fail create 
fi
tpm2_load  -H $Handle_parent   -u $file_load_key_pub  -r $file_load_key_priv -n $file_load_key_name -C $file_load_key_ctx
if [ $? != 0 ];then
	fail load   
fi
echo "load test OK!"

