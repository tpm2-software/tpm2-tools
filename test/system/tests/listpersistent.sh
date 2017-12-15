#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2017, Red Hat, Inc.
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

handle_base=0x81000000
auth=o

declare -a hashes=("sha1" "sha256")
declare -a keys=("ecc" "keyedhash")

cleanup() {
    for idx in "${!keys[@]}"
    do
        handle=$(printf "0x%X\n" $(($handle_base + $idx)))
        tpm2_evictcontrol -Q -A "$auth" -H "$handle" -S "$handle"
    done

    rm -f primary.context
}

trap cleanup EXIT

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

tpm2_takeownership -c

# Test persisting transient objects
for idx in "${!keys[@]}"
do
    tpm2_createprimary -Q -H "$auth" -g "${hashes[$idx]}" -G "${keys[$idx]}" -C primary.context
    handle=$(printf "0x%X\n" $(($handle_base + $idx)))
    tpm2_evictcontrol -Q -A "$auth" -S "$handle" -c primary.context
done

handle_cnt=$(tpm2_listpersistent | wc -l)

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
