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

  rm -f policy.bin obj.pub pub.out

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
        for Atype in o e n; do
            tpm2_createprimary -Q -H $Atype -g $gAlg -G $GAlg -C context.out
            cleanup keep_context
        done
    done
done

function yaml_get() {

python << pyscript
from __future__ import print_function

import sys
import yaml

with open("$2") as f:
	try:
		y = yaml.load(f)
		found = "$1" in y
		if (not found):
			sys.stderr.write('Could not find index 0x%X\n' % ("$1"))
		print(y["$1"])
		sys.exit(not found)
	except yaml.YAMLError as exc:
		sys.exit(exc)
pyscript
}

policy_orig="f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988"

#test for createprimary objects with policy authorization structures
echo -n "$policy_orig" | xxd -r -p > policy.bin

tpm2_createprimary -Q -H o -G rsa -g sha256 -C context.out -L policy.bin \
  -A 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin'

tpm2_readpublic -c context.out > pub.out

policy_new=$(yaml_get "authorization policy" pub.out)

test "$policy_orig" == "$policy_new"

exit 0
