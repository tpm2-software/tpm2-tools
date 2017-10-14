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

source test_helpers.sh

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

cleanup() {

  rm -f policy.bin obj.pub

  if [ "$1" != "keep_context" ]; then
    rm -f context.out
  fi

}
trap cleanup EXIT

cleanup

# Keep the algorithm specifiers mixed to test friendly and raw
# values.
for gAlg in `populate_hash_algs mixed`; do
    for GAlg in 0x01 keyedhash ecc 0x25; do
        for Atype in o e p n; do
            tpm2_createprimary -Q -A $Atype -g $gAlg -G $GAlg -C context.out
            cleanup keep_context
        done
    done
done

#test for createprimary objects with policy authorization structures
echo "f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988" \
| xxd -r -p > policy.bin

tpm2_createprimary -Q -A o -G rsa -g sha256 -E -C context.out -L policy.bin

tpm2_readpublic -Q -c context.out -o obj.pub

cmp -i 14:0 -n 32 obj.pub policy.bin -s

exit 0
