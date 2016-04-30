#!/bin/bash
new_path=`pwd`
PATH="$PATH":"$new_path"

alg_primary_obj=0x000B
alg_primary_key=0x0001
alg_create_obj=0x000B
alg_create_key=0x0008

alg_quote=0x0004

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_quote_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_quote_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_quote_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_quote_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_quote_output=quote_"$file_quote_key_ctx"

Handle_ak_quote=0x81010016
Handle_ek_quote=0x81010017

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

rm $file_primary_key_ctx $file_quote_key_pub $file_quote_key_priv $file_quote_key_name $file_quote_key_ctx  $file_quote_output  -rf


tpm2_takeownership -c

tpm2_createprimary -A e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx
if [ $? != 0 ];then
	 fail createprimary 
	 exit 1
fi
tpm2_create -g $alg_create_obj -G $alg_create_key -o $file_quote_key_pub -O $file_quote_key_priv  -c $file_primary_key_ctx
if [ $? != 0 ];then
	fail create 
	exit 1
fi

tpm2_load -c $file_primary_key_ctx  -u $file_quote_key_pub  -r $file_quote_key_priv -n $file_quote_key_name -C $file_quote_key_ctx
if [ $? != 0 ];then
	fail load   
fi

tpm2_quote -c $file_quote_key_ctx  -g 0x4 -l 16,17,18 -o $file_quote_output
if [ $? != 0 ];then
	fail decrypt 
fi

#####handle testing
tpm2_evictcontrol -A o -c $file_quote_key_ctx  -S $Handle_ak_quote
if [ $? != 0 ];then
	fail evict 
fi
 
rm quote_handle_output_"$Handle_ak_quote" -rf
tpm2_quote -k $Handle_ak_quote  -g $alg_quote -l 16,17,18 -o quote_handle_output_"$Handle_ak_quote"
if [ $? != 0 ];then
	fail quote_handle 
fi

#####AK
Handle_ak_quote=$(($Handle_ak_quote+0x2))
val=`echo 'obase=16;'$Handle_ak_quote''|bc`
Handle_ak_quote=0x"$val"
tpm2_getpubek  -H  $Handle_ek_quote -g 0x01 -f ek.pub2  
if [ $? != 0 ];then
	fail getpubek 
fi
tpm2_getpubak  -E  $Handle_ek_quote -k  $Handle_ak_quote -f ak.pub2 -n ak.name_2  
if [ $? != 0 ];then
	fail getpubak 
fi

rm quote_handle_output_"$Handle_ak_quote" -rf
tpm2_quote -k  $Handle_ak_quote -g $alg_quote -l 16,17,18 -o quote_handle_output_"$Handle_ak_quote"
if [ $? != 0 ];then
	fail quote_handle_ak 
fi
echo "quote test OK!"

