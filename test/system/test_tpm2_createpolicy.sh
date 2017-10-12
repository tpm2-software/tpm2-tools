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
    rm -f policy.out &>/dev/null
}
trap cleanup EXIT

declare -A expected_policy_digest=(["sha1"]="f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988"
                                   ["sha256"]="33e36e786c878632494217c3f490e74ca0a3a122a8a4f3c5302500df3b32b3b8")

for halg in sha1 sha256
do
    cleanup

    #
    # This script expects PCR index 0 to be equal to 0x03
    #
    value=`tpm2_pcrlist -L $halg:0 | grep PCR_00 | cut -d\: -f 2-`
    if [[ 16#$value -ne 0x03 ]]; then
        echo "Expected PCR 0 \"$halg\" bank to be 0x3, found: \"$value\"" 1>&2
        exit 1
    fi

    tpm2_createpolicy -P -L $halg:0 -f policy.out

    # Test the policy creation hashes against expected
    if [ $(xxd -p policy.out | tr -d '\n' ) != "${expected_policy_digest[${halg}]}" ]; then
        echo "Failure: Creating Policy Digest with PCR policy for index 0 and ${halg} pcr index hash"
        exit 1
    fi
done

exit 0
