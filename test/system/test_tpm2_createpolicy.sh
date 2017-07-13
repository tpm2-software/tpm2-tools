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
###this script use for test the implementation tpm2_createpolicy

#!/bin/sh

declare -A expected_policy_digest=(["sha1"]="f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988"
                                   ["sha256"]="33e36e786c878632494217c3f490e74ca0a3a122a8a4f3c5302500df3b32b3b8")
declare -A hash_name=([0x4]="sha1" [0xb]="sha256")
pcr_index=0

for halg in 0x4 0xb
do
    hash=${hash_name[${halg}]}
    tpm2_createpolicy -f policy.file -P -L ${halg}:${pcr_index} 
    if [ $? != 0 ];then
        echo "createpolicy command failed, please check the environment or parameters!"
        exit 1
    fi

    if [ $(xxd -p policy.file | tr -d '\n' ) != "${expected_policy_digest[${hash}]}" ];then
        echo "Failure: Creating Policy Digest with PCR policy for index ${pcr_index} and ${hash} pcr index hash"
        exit 1
    else
        echo "Success: Creating Policy Digest with PCR policy for index ${pcr_index} and ${hash} pcr index hash"
    fi
done

if [ ! -f policy.file ]; then
 echo "Policy File not found!"
else
 rm -f policy.file
fi

echo "passed pcr policy test"
