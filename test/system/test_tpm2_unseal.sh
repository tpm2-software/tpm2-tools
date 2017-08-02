#;**********************************************************************;
#
# Copyright (c) 2016, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, 
# this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, 
# this list of conditions and the following disclaimer in the documentation 
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;
#!/bin/bash
alg_primary_obj=0x0004
alg_primary_key=0x0001
alg_create_obj=0x000B
alg_create_key=0x0008
alg_pcr_policy=0x0004

pcr_ids="0,1,2,3"

obj_attr=0x492 # fixedTPM, fixedParent, adminWithPolicy, noDA

file_pcr_value=pcr.bin
file_input_data=secret.data
file_policy=policy.data
file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_unseal_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_unseal_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_unseal_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_unseal_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_unseal_output_data=usl_"$file_unseal_key_ctx"

secret="12345678"

rm $file_primary_key_ctx $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_ctx $file_unseal_key_name $file_unseal_output_data -rf

if [ ! -e "$file_input_data" ]   
  then    
echo $secret > $file_input_data
fi 

tpm2_takeownership -c
tpm2_createprimary -A e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx
if [ $? != 0 ];then
echo "createprimary fail, please check the environment or parameters!"
exit 1
fi

tpm2_create -g $alg_create_obj -G $alg_create_key -o $file_unseal_key_pub -O $file_unseal_key_priv  -I $file_input_data -c $file_primary_key_ctx
if [ $? != 0 ];then
echo "create fail, please check the environment or parameters!"
exit 1
fi

tpm2_load -c $file_primary_key_ctx  -u $file_unseal_key_pub  -r $file_unseal_key_priv -n $file_unseal_key_name -C $file_unseal_key_ctx
if [ $? != 0 ];then
echo "load fail, please check the environment or parameters!"
exit 1
fi

tpm2_unseal -c $file_unseal_key_ctx -o $file_unseal_output_data
if [ $? != 0 ];then
echo "unseal fail, please check the environment or parameters!"
exit 1
fi

cmp -s $file_unseal_output_data $file_input_data
if [ $? != 0 ]; then
    echo "unseal fail, output differs from sealed data!"
    exit 1
fi

# Test using a PCR policy for auth

rm $file_unseal_key_pub $file_unseal_key_priv $file_unseal_key_name

tpm2_pcrlist -L ${alg_pcr_policy}:${pcr_ids} -o $file_pcr_value
if [ $? != 0 ];then
    echo "create raw pcr output fail, please check the environment or parameters!"
    exit 1
fi

tpm2_createpolicy -P -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value -f $file_policy
if [ $? != 0 ];then
    echo "create policy fail, please check the environment or parameters!"
    exit 1
fi

tpm2_create -g $alg_create_obj -G $alg_create_key -o $file_unseal_key_pub -O $file_unseal_key_priv -I- -c $file_primary_key_ctx -L $file_policy -A $obj_attr <<< $secret
if [ $? != 0 ];then
    echo "create object with policy fail, please check the environment or parameters!"
    exit 1
fi

tpm2_load -c $file_primary_key_ctx  -u $file_unseal_key_pub  -r $file_unseal_key_priv -n $file_unseal_key_name -C $file_unseal_key_ctx
if [ $? != 0 ];then
    echo "load fail, please check the environment or parameters!"
    exit 1
fi

unsealed=`tpm2_unseal -c $file_unseal_key_ctx -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value`
if [ $? != 0 ];then
    echo "unseal fail, please check the environment or parameters!"
    exit 1
fi

if [ "$unsealed" != "$secret" ];then
    echo "unseal fail, output differs from sealed data!"
    exit 1
fi

echo "tpm2_unseal success"
exit 0
