#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

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
        y = yaml.safe_load(f)
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
