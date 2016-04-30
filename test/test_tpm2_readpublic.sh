#!/bin/bash
new_path=`pwd`
PATH="$PATH":"$new_path"

alg_primary_obj=0x000B
alg_primary_key=0x0001
alg_create_obj=0x000B
alg_create_key=0x0008

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_readpub_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_readpub_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_readpub_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_readpub_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_readpub_output=readpub_"$file_readpub_key_ctx"

Handle_readpub=0x81010014

fail()
{
	    echo "$1 test fail, pelase check the environment or parameters!"
        exit 1
}
Pass()
{
	    echo ""$1" pass" >>test_getpubak_pass.log
}

rm $file_primary_key_ctx $file_readpub_key_pub $file_readpub_key_priv $file_readpub_key_name $file_readpub_key_ctx  $file_readpub_output  -rf

tpm2_takeownership -c

tpm2_createprimary -A e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx
if [ $? != 0 ];then
	 fail createprimary 
fi
tpm2_create -g $alg_create_obj -G $alg_create_key -o $file_readpub_key_pub -O $file_readpub_key_priv  -c $file_primary_key_ctx
if [ $? != 0 ];then
	fail create 
fi

tpm2_load -c $file_primary_key_ctx  -u $file_readpub_key_pub  -r $file_readpub_key_priv -n $file_readpub_key_name -C $file_readpub_key_ctx
if [ $? != 0 ];then
	fail load   
fi

tpm2_readpublic -c $file_readpub_key_ctx -o $file_readpub_output
if [ $? != 0 ];then
	fail decrypt 
fi

#####handle testing
tpm2_evictcontrol -A o -c $file_readpub_key_ctx  -S $Handle_readpub
if [ $? != 0 ];then
	fail evict 
fi
 
rm $file_readpub_output -rf
tpm2_readpublic -H $Handle_readpub -o $file_readpub_output
if [ $? != 0 ];then
	fail readpublic_handle 
fi

echo "readpublic test OK!"

