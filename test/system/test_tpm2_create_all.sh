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

new_path=`dirname $0`
PATH="$PATH":"$new_path"
pCtx=
gAlg=
GAlg=

rm create.error.log

ctx_count=`ls |grep -c context_load`
if [ $ctx_count -le 1 ];then
	echo "we should execute test_tpm2_createprimary_all.sh first!"
	wait 5
    test_tpm2_createprimary_all.sh
fi

for pCtx in `ls ctx.cpri*`
    do
    for gAlg in sha1 0x0B sha384 0x0D 0x12
        do 
        for GAlg in rsa 0x08 ecc 0x25
            do 
            tpm2_create -c $pCtx -g $gAlg -G $GAlg -o opu."$pCtx".g"$gAlg".G"$GAlg" -O opr."$pCtx".g"$gAlg".G"$GAlg"
            if [ $? != 0 ];then 
            echo "tpm2_create error: pCtx=$pCtx gAlg=$gAlg GAlg=$GAlg"
            echo "tpm2_create error: pCtx=$pCtx gAlg=$gAlg GAlg=$GAlg" >> create.error.log             
            fi
        done
    done
done

echo "f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988" \
| xxd -r -p > policy.bin

tpm2_createprimary -A o -g 0xb -C prim.ctx -G 0x1
if [ $? != 0 ];then
 echo "create primary failed"
 exit 1
fi

tpm2_create -c prim.ctx -g sha256 -G 0x1 -L policy.bin -o key.pub -O key.priv -E
if [ $? != 0 ];then
 echo "create object failed"
 exit 1
fi

cmp -i 4:0 -n 32 key.pub policy.bin -s
if [ $? != 0 ];then
 echo "tpm2_create_error: Policy digest did not match in auth structure" >> create.error.log
 exit 1
fi 

rm -f prim.ctx policy.bin key.priv key.pub
exit 0
