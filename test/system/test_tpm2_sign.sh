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

file_primary_key_ctx=context.p_B1
file_signing_key_pub=opuB1_B8
file_signing_key_priv=oprB1_B8
file_signing_key_ctx=context_load_out_B1_B8
file_signing_key_name=name.load.B1_B8
file_input_data=secret.data
file_output_data=sig.4

  
handle_signing_key=0x81010005

alg_hash=sha256
alg_primary_key=0x0001
alg_signing_key=0x0008

fail()
{
	    echo "$1 test fail, please check the environment or parameters!"
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
grep "persistentHandle: "$handle_signing_key"" evict.log
c2="$?"

if [ $c1 != 0 ] || [ $c2 != 0  ];then
     fail evictcontrol 
fi

tpm2_sign -k $handle_signing_key -g $alg_hash -m $file_input_data -s $file_output_data

if [ $? != 0 ];then
    fail sign
fi

