#!/bin/bash
new_path=`pwd`
PATH="$PATH":"$new_path"

file_primary_key_ctx=context.p_B1
file_evict_key_pub=opuB1_B8
file_evict_key_priv=oprB1_B8
file_evict_key_ctx=context_load_out_B1_B8
file_evict_key_name=name.load.B1_B8
  
persistentHandle=0x81010003


alg_hash=0x000B
alg_primary_key=0x0001
alg_evict_key=0x0008


rm $file_primary_key_ctx $file_evict_key_pub $file_evict_key_priv $file_evict_key_ctx $file_evict_key_name $file_output_data -rf

tpm2_takeownership -c

tpm2_createprimary -A e -g $alg_hash -G $alg_primary_key -C $file_primary_key_ctx
if [ $? != 0 ];then
 echo "createprimary fail, pelase check the environment or parameters!"
 exit 1
fi
tpm2_create -g $alg_hash -G $alg_evict_key -o $file_evict_key_pub -O $file_evict_key_priv  -c $file_primary_key_ctx
if [ $? != 0 ];then
 echo "create fail, pelase check the environment or parameters!"
 exit 1
fi
tpm2_load -c $file_primary_key_ctx  -u $file_evict_key_pub  -r $file_evict_key_priv -n $file_evict_key_name -C $file_evict_key_ctx
if [ $? != 0 ];then
 echo "load fail, pelase check the environment or parameters!"
 exit 1
fi

tpm2_evictcontrol -A o -c $file_evict_key_ctx  -S $persistentHandle
if [ $? != 0 ];then
 echo "evictontronl persistentHandle fail, pelase check the environment or parameters!"
 exit 1
else
 tpm2_evictcontrol -A o -H $persistentHandle   -S $persistentHandle
 if [ $? != 0 ];then
  echo "evictcontrol release Handle fail, pelase check the environment or parameters!"
  exit 1
 fi
fi

