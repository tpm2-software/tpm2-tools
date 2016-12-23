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
#!/bin/sh

##before this script, you should make sure all kinds of context already loaded 

context_p=
halg=
new_path=`dirname $0`
PATH="$PATH":"$new_path"

ctx_count=`ls |grep -c context_load`
if [ $ctx_count -le 1 ];then
	echo "we should execute test_algs.sh first!"
	wait 5
	test_algs.sh
fi

rm test_algs_encryptdecrypt_*.log

if [ ! -e "secret.data" ]   
  then    
echo "12345678" > secret.data
fi 

#for  halg_p in 0x0004 0x000B 0x000C 0x000D 0x0012  
for  context_p in `ls context_load*`   
  do
	
	tpm2_encryptdecrypt -c  $context_p  -D NO -I secret.data -o endecrypt_"$context_p".f


	 if [ $? != 0 ];then
	 echo "encryptdecrypt  for  endecrypt_"$context_p".f fail, please check the environment or parameters!"
	 echo "encryptdecrypt  for  endecrypt_"$context_p".f fail" >>test_encryptdecrypt_error.log
	else
	 echo "encryptdecrypt  for  endecrypt_"$context_p".f pass" >>test_encryptdecrypt_pass.log
        tpm2_encryptdecrypt -c  $context_p  -D YES -I  endecrypt_"$context_p".f -o decrypt_"$context_p".f
	
	  if [ $? != 0 ];then
	  echo "encryptdecrypt  for  decrypt_"$context_p".f fail, please check the environment or parameters!"
	  echo "encryptdecrypt  for  decrypt_"$context_p".f fail" >>test_encryptdecrypt_error.log
	 else
	  echo "encryptdecrypt  for  decrypt_"$context_p".f pass" >>test_encryptdecrypt_pass.log
	 fi
	fi

 done
