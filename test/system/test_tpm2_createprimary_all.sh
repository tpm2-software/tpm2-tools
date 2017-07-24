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

Atype=
gAlg=
GAlg=

rm createprimary.error.log rf
for gAlg in 0x04 sha256 0x0C 0x0D sm3_256
    do 
        for GAlg in 0x01 keyedhash ecc 0x25
            do 
                for Atype in o e p n 
                    do 
                    tpm2_createprimary -A $Atype -g $gAlg -G $GAlg -C ctx.cpri."$Atype".g"$gAlg".G"$GAlg"
                    if [ $? != 0 ];then 
                    echo "tpm2_createprimary error: Atype=$Atype gAlg=$gAlg GAlg=$GAlg"
                    echo "tpm2_createprimary error: Atype=$Atype gAlg=$gAlg GAlg=$GAlg" >> createprimary.error.log
                    fi
                done
        done
done

#test for createprimary objects with policy authorization structures
echo "f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988" \
| xxd -r -p > policy.bin

tpm2_createprimary  -A o -G 0x1 -g 0xb -E -C prim.ctx -L policy.bin
if [ $? != 0 ];then
 exit 1
fi

tpm2_readpublic -c prim.ctx -o testprim.pub
if [ $? != 0 ];then
 exit 1
fi

cmp -i 14:0 -n 32 testprim.pub policy.bin -s
if [ $? != 0 ];then
 echo "Failed: createprimary with policy authorization structure" >> createprimary.error.log
 exit 1
fi

rm -f prim.ctx policy.bin testprim.pub
exit 0
