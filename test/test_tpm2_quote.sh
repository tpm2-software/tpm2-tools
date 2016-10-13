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
alg_primary_obj=0x000B
alg_primary_key=0x0001
alg_create_obj=0x000B
alg_create_key=0x0008

alg_quote=0x0004
alg_quote1=0x000b

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_quote_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_quote_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_quote_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_quote_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_quote_output=quote_"$file_quote_key_ctx"

Handle_ak_quote=0x81010016
Handle_ek_quote=0x81010017

nonce=12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde

fail()
{
	    echo "$1 test fail, please check the environment or parameters!"
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

tpm2_quote -c $file_quote_key_ctx  -g $alg_quote -l 16,17,18 -o $file_quote_output -q $nonce
if [ $? != 0 ];then
	fail quote 
fi

rm $file_quote_output -rf
tpm2_quote -c $file_quote_key_ctx  -L $alg_quote:16,17,18+$alg_quote1:16,17,18 -o $file_quote_output -q $nonce
if [ $? != 0 ];then
	fail quote 
fi

#####handle testing
tpm2_evictcontrol -A o -c $file_quote_key_ctx  -S $Handle_ak_quote
if [ $? != 0 ];then
	fail evict 
fi
 
rm quote_handle_output_"$Handle_ak_quote" -rf
tpm2_quote -k $Handle_ak_quote  -g $alg_quote -l 16,17,18 -o quote_handle_output_"$Handle_ak_quote" -q $nonce
if [ $? != 0 ];then
	fail quote_handle 
fi

rm quote_handle_output_"$Handle_ak_quote" -rf
tpm2_quote -k $Handle_ak_quote  -L $alg_quote:16,17,18+$alg_quote1:16,17,18 -o quote_handle_output_"$Handle_ak_quote" -q $nonce
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
tpm2_quote -k  $Handle_ak_quote -g $alg_quote -l 16,17,18 -o quote_handle_output_"$Handle_ak_quote" -q $nonce
if [ $? != 0 ];then
	fail quote_handle_ak 
fi
echo "quote test OK!"

