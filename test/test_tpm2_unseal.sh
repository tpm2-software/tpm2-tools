#!/bin/bash
new_path=`pwd`
PATH="$PATH":"$new_path"

alg_primary_obj=0x0004
alg_primary_key=0x0001
alg_create_obj=0x000B
alg_create_key=0x0008

file_input_data=secret.data
file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_unseal_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_unseal_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_unseal_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_unseal_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_unseal_output_data=usl_"$file_unseal_key_ctx"
  
rm $file_primary_key_ctx $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_ctx $file_unseal_key_name $file_unseal_output_data -rf

if [ ! -e "$file_input_data" ]   
  then    
echo "12345678" > $file_input_data
fi 

tpm2_takeownership -c
tpm2_createprimary -A p -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx
if [ $? != 0 ];then
echo "createprimary fail, pelase check the environment or parameters!"
exit 1
fi
#./tpm2_create -g 0x000B -G 0x0008 -o opu9.out -O opr9.out -c context.p9.out -I secret.data
tpm2_create -g $alg_create_obj -G $alg_create_key -o $file_unseal_key_pub -O $file_unseal_key_priv  -I $file_input_data -c $file_primary_key_ctx
if [ $? != 0 ];then
echo "create fail, pelase check the environment or parameters!"
exit 1
fi
#./tpm2_load -c context.p9.out  -u opu9.out -r opr9.out -n name.load9.out -C context_load_out9.out 
tpm2_load -c $file_primary_key_ctx  -u $file_unseal_key_pub  -r $file_unseal_key_priv -n $file_unseal_key_name -C $file_unseal_key_ctx
if [ $? != 0 ];then
echo "load fail, pelase check the environment or parameters!"
exit 1
fi

#tpm2_unseal -c context_load_out1.out -o usl.data.out
tpm2_unseal -c $file_unseal_key_ctx $ -o $file_unseal_output_data 
if [ $? != 0 ];then
echo "unseal fail, pelase check the environment or parameters!"
exit 1
fi

###handle test blocked 
##tpm2_evictcontrol -A p -c $file_unseal_key_ctx  -S 0x81010015 --Fail to evict
##tpm2_evictcontrol -A o -c context_load_out4  -S 0x81010015 (0x285)
##tpm2_unseal -H 0x81010015 -o usl_handle
