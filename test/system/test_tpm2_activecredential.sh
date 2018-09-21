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

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

cleanup() {
    rm -f secret.data ek.pub ak.pub ak.name mkcred.out actcred.out ak.out

    # Evict persistent handles, we want them to always succeed and never trip
    # the onerror trap.
	tpm2_evictcontrol -Q -A o -H 0x81010009 2>/dev/null || true
	tpm2_evictcontrol -Q -A o -H 0x8101000a 2>/dev/null || true
}
trap cleanup EXIT

cleanup

echo "12345678" > secret.data

tpm2_getpubek -Q -H 0x81010009 -g rsa -f ek.pub

tpm2_getpubak -E 0x81010009 -k 0x8101000a -g rsa -D sha256 -s rsassa -f ak.pub -n ak.name > ak.out

# Capture the yaml output and verify that its the same as the name output
loaded_key_name_yaml=`python << pyscript
from __future__ import print_function
import yaml

with open('ak.out', 'r') as f:
    doc = yaml.load(f)
    print(doc['loaded-key']['name'])
pyscript`

# Use -c in xxd so there is no line wrapping
file_size=`stat --printf="%s" ak.name`
loaded_key_name=`cat ak.name | xxd -p -c $file_size`

test "$loaded_key_name_yaml" == "$loaded_key_name"

tpm2_makecredential -Q -e ek.pub  -s secret.data -n $loaded_key_name -o mkcred.out

tpm2_activatecredential -Q -H 0x8101000a -k 0x81010009 -f mkcred.out -o actcred.out

exit 0
