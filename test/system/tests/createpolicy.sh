#!/bin/bash
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

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

cleanup() {
    rm -f pcr.in policy.out
}
trap cleanup EXIT

declare -A digestlengths=(["sha1"]=20 ["sha256"]=32)
declare -A expected_policy_digest=(["sha1"]="f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988"
                                   ["sha256"]="33e36e786c878632494217c3f490e74ca0a3a122a8a4f3c5302500df3b32b3b8")

for halg in ${!digestlengths[@]}
do
    cleanup

    # Create file containing expected PCR value
    head -c $((${digestlengths[$halg]} - 1)) /dev/zero > pcr.in
    echo -n -e '\x03' >> pcr.in

    tpm2_createpolicy -P -L $halg:0 -F pcr.in -f policy.out

    # Test the policy creation hashes against expected
    if [ $(xxd -p policy.out | tr -d '\n' ) != "${expected_policy_digest[${halg}]}" ]; then
        echo "Failure: Creating Policy Digest with PCR policy for index 0 and ${halg} pcr index hash"
        exit 1
    fi
done

exit 0
