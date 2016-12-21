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
###this script use for test the implementation of all algorithms involved createprimary &create/load 

#!/bin/sh
halg_p=
kalg_p=

halg_c=
kalg_c=

rm *.log  context*  op* name.load*

for  halg_p in 0x0004 0x000B 0x000C 0x000D 0x0012  
# for  halg_p in 0x0004 0x000B 0x000C
   do
    for kalg_p in 0x0001 0x0008 0x0023 0x0025
      do
 
     tpm2_createprimary -A e -g $halg_p  -G $kalg_p -C context.p_"$halg_p"_"$kalg_p"
     if [ $? != 0 ];then
     echo "createprimary for context.p_"$halg_p"_"$kalg_p" fail, please check the environment or      parameters!"
     fi
 
 ############create & load key context############ 
 for  halg_c in 0x0004 0x000B 0x000C 0x000D 0x0012
 do
	for kalg_c in 0x0001 0x0008 0x0023 0x0025
	 do
     tpm2_create  -g $halg_c  -G $kalg_c -o opu_"$halg_p""$kalg_p"_"$halg_c""$kalg_c" -O opr_"$halg_p""$kalg_p"_"$halg_c""$kalg_c"  -c context.p_"$halg_p"_"$kalg_p"
    
		if [ $? != 0 ];then
		echo "create used context.p_"$halg_p"_"$kalg_p" with algs:"$halg_c""$kalg_c" fail, please check the environment or parameters!" 
		echo "create used context.p_"$halg_p"_"$kalg_p" with algs:"$halg_c""$kalg_c" fail" >>create_error.log 

	else

		 tpm2_load -c context.p_"$halg_p"_"$kalg_p"  -u opu_"$halg_p""$kalg_p"_"$halg_c""$kalg_c"  -r opr_"$halg_p""$kalg_p"_"$halg_c""$kalg_c"  -n name.load_"$halg_p""$kalg_p"_"$halg_c""$kalg_c" -C context_load_"$halg_p""$kalg_p"_"$halg_c""$kalg_c"
		if [ $? != 0 ];then
		echo "load for context.p_"$halg_p"_"$kalg_p"  fail, please check the environment or      parameters!"
		echo "load context.p_"$halg_p"_"$kalg_p" for create  context_load_"$halg_p""$kalg_p"_"$halg_c""$kalg_c" fail" >>load_error.log
		fi
	
     fi
	 done
	done

 done
done
