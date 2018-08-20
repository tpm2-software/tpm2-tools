#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2017, Red Hat, Inc.
# Copyright (c) 2018, Intel Corporation
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

source helpers.sh

handle_base=0x81000000
auth=o

declare -a hashes=("sha1" "sha256")
declare -a keys=("ecc" "xor")

cleanup() {
    for idx in "${!keys[@]}"
    do
        handle=$(printf "0x%X\n" $(($handle_base + $idx)))
        tpm2_evictcontrol -Q -a "$auth" -c "$handle"
    done

    rm -f primary.context out.yaml

    shut_down
}
trap cleanup EXIT

start_up

function yaml_get_len() {

python << pyscript
from __future__ import print_function

import sys
import yaml

with open("$1") as f:
    try:
        y = yaml.load(f)
        print(len(y))
    except yaml.YAMLError as exc:
        sys.exit(exc)
pyscript
}

tpm2_clear

# Test persisting transient objects
for idx in "${!keys[@]}"
do
    tpm2_createprimary -Q -a "$auth" -g "${hashes[$idx]}" -G "${keys[$idx]}" -o primary.context
    handle=$(printf "0x%X\n" $(($handle_base + $idx)))
    tpm2_evictcontrol -Q -a "$auth" -p "$handle" -c primary.context
done

tpm2_listpersistent > out.yaml

handle_cnt=$(yaml_get_len out.yaml)

if [ "$handle_cnt" -ne "${#keys[@]}" ]; then
    echo "Only $handle_cnt of ${#keys[@]} persistent objects were listed"
    exit 1
fi

# Test filtering by key algorithm
for alg in "${keys[@]}"
do
    tpm2_listpersistent -G "$alg" | grep -q "$alg"
done

# Test filtering by hash algorithm
for hash in "${hashes[@]}"
do
    tpm2_listpersistent -g "$hash" | grep -q "$hash"
done

# Test filtering by both hash and key algorithms
tpm2_listpersistent -g "${hashes[0]}" -G "${keys[0]}" | grep -q "${hashes[0]}"
tpm2_listpersistent -g "${hashes[0]}" -G "${keys[0]}" | grep -q "${keys[0]}"

exit 0
