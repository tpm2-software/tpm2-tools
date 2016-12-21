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
handle_ek=0x81010005
##ek_e=1
ek_alg=0x0001

handle_ak=0x81010006
ak_alg=
digestAlg= 
signAlg=

fail()
{
	echo "$1 test fail, please check the environment or parameters!"
	echo ""$1" fail" >>test_getpubak_error.log
}	

Pass()
{
	echo ""$1" pass" >>test_getpubak_pass.log
}


rm test_getpub*.log
rm ak.pub*

tpm2_getpubek  -H "$handle_ek" -g $ek_alg -f ek.pub_"$ek_alg" 
if [ $? != 0 ];then
    fail getpubek
	exit 1
fi
##   ./tpm2_getpubak  -e "$handle_ek" -k $handle_ak  -g $ak_alg -D $digestAlg -s $signAlg -f ak.pub_"$kalg_p"_"$halg"_"$digestAlg"_"$signAlg" -n ak.name_"$kalg_p"_"$halg"_"$digestAlg"_"$signAlg"

for  ak_alg in 0x0001 0x0008 0x0023  
 do
   for  digestAlg in 0x0004 0x000B 0x000C 0x000D 0x0012
   do 
    for  signAlg in 0x0005 0x0014 0x0016 0x0018 0x001A 0x001B 0x001C
    do

  tpm2_getpubak  -E "$handle_ek" -k $handle_ak  -g $ak_alg -D $digestAlg -s $signAlg -f ak.pub_"$ak_alg"_"$digestAlg"_"$signAlg" -n ak.name_"$ak_alg"_"$digestAlg"_"$signAlg"
  if [ $? != 0 ];then
    fail "Ak_alg_"$ak_alg"_"$digestAlg"_"$signAlg""
  else
    Pass "Ak_alg_"$ak_alg"_"$digestAlg"_"$signAlg""
  fi
  handle_ak=$(($handle_ak+0x1))
  val=`echo 'obase=16; '$handle_ak''|bc`
  handle_ak=0x"$val"
  done
 done
done

