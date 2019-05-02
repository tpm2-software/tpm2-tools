#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
# All rights reserved.
#
#;**********************************************************************;

source helpers.sh

cleanup() {
    rm -f secret.data ek.pub ak.pub ak.name mkcred.out actcred.out ak.out

    # Evict persistent handles, we want them to always succeed and never trip
    # the onerror trap.
    tpm2_evictcontrol -Q -a o -c 0x81010009 2>/dev/null || true
    tpm2_evictcontrol -Q -a o -c 0x8101000a 2>/dev/null || true

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo "12345678" > secret.data

tpm2_createek -Q -c 0x81010009 -G rsa -p ek.pub

tpm2_createak -C 0x81010009 -k 0x8101000a -G rsa -D sha256 -s rsassa -p ak.pub -n ak.name > ak.out

# Capture the yaml output and verify that its the same as the name output
loaded_key_name_yaml=`python << pyscript
from __future__ import print_function

import yaml

with open('ak.out', 'r') as f:
    doc = yaml.safe_load(f)
    print(doc['loaded-key']['name'])
pyscript`

# Use -c in xxd so there is no line wrapping
file_size=`stat --printf="%s" ak.name`
loaded_key_name=`cat ak.name | xxd -p -c $file_size`

test "$loaded_key_name_yaml" == "$loaded_key_name"

tpm2_makecredential -Q -e ek.pub  -s secret.data -n $loaded_key_name -o mkcred.out

tpm2_activatecredential -Q -c 0x8101000a -C 0x81010009 -i mkcred.out -o actcred.out

exit 0
