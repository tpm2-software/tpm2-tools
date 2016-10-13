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
#handle_ek=0x81010003
ek_e=1
handle_k=
kalg_p=
halg=
digestAlg= 
signAlg=

fail()
{
	echo "getpubek  for ek.pub_"$1" fail, please check the environment or parameters!"
	echo "getpubek  for ek.pub_"$1" fail" >>test_getpubek_error.log
}	

Pass()
{
	echo "getpubek  for ek.pub_"$1" pass" >>test_getpubak_pass.log
}



rm test_getpub*.log
rm ek.pub*

for  kalg_p in 0x0001 0x0008 0x0023 0x0025   
 do
##echo $ek_e	
 tpm2_getpubek  -H 0x8101000"$ek_e" -g $kalg_p -f ek.pub_"$kalg_p" 
  if [ $? != 0 ];then
    fail "$kalg_p"
  else
    Pass "$kalg_p"
  fi
 ek_e=$(($ek_e+2))
 done
