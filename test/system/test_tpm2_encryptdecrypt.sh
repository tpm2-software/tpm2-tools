#!/bin/bash
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
encrypt_decrypt_cc=0x164
tpm2_dump_capability -c commands | grep $encrypt_decrypt_cc
if [ $? != 0 ];then
    echo "Command EncryptDecrypt is not supported by your device"
    exit 0
fi

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
	    echo "$1 test fail, please check the environment or parameters!"
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
if [ $? != 0 ];then
    fail takeownership
fi

tpm2_createprimary -A e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx
if [ $? != 0 ];then
	 fail createprimary 
fi
tpm2_create -g $alg_create_obj -G $alg_create_key -u $file_en_decrypt_key_pub -r $file_en_decrypt_key_priv  -c $file_primary_key_ctx
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

