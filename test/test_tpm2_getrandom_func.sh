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
#this script for tpm2_getrandom verification 

LOG_FILE=random_pass_count.log
 if [ -e "$LOG_FILE" ];then
  rm -f "$LOG_FILE"
 fi
i=

#for((i=1;i<=10;i++)); do
for i in `seq 100`; do
	tpm2_getrandom -s 32  -o random_"$i".out 
	 if  [ $? != 0 ];then
	  echo " create random_"$i".out fail, please check the environment or parameters!"
	  exit 2
	 else
	  echo  "create random_"$i".out Pass" >>$LOG_FILE
	 fi
done

for a in `seq 99` ;do
   b=$(($a+1)) 

	while [ $b -le 100 ]; do
	diff "random_"$a".out" "random_"$b".out" >/dev/null 
	 if [ $? -eq 0 ];then
	  echo "random test fial"
	  exit 1
	 fi
	b=$(($b+1))
	done

done 

echo  "random test Pass"
