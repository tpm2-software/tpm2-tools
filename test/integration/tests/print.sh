#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

ak_ctx=ak.ctx
ek_handle=0x81010017

ak_name_file=ak.name
ak_pubkey_file=ak.pub
ek_pubkey_file=ek.pub

quote_file=quote.bin
print_file=quote.yaml

cleanup() {
    rm -f $ak_name_file $ak_pubkey_file $ek_pubkey_file \
          $quote_file $print_file $ak_ctx

    if [ "$1" != "no-shut-down" ]; then
       shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear

# Create signing key
tpm2_createek -Q -G rsa -c $ek_handle -p $ek_pubkey_file
tpm2_createak -Q -G rsa -D sha256 -s rsassa -C $ek_handle -c $ak_ctx -p $ak_pubkey_file -n $ak_name_file

# Take PCR quote
tpm2_quote -Q -C $ak_ctx -L "sha256:0,2,4,9,10,11,12,17" -q "0f8beb45ac" -m $quote_file

# Print TPM's quote file
tpm2_print -t TPMS_ATTEST -i $quote_file > $print_file

# Check printed yaml
python << pyscript
from __future__ import print_function

import sys
import re
import yaml

with open("$print_file") as fd:
    yaml = yaml.safe_load(fd)

    assert(yaml["magic"] == "ff544347")
    assert(yaml["type"] == 8018)
    assert(yaml["extraData"] == "0f8beb45ac")

    quote = yaml["attested"]["quote"]

    # there should be only one pcr selection
    assert(quote["pcrSelect"]["count"] == 1)

    pcr_select = quote["pcrSelect"]["pcrSelections"][0]

    # pcr selection should match above options
    assert(pcr_select["hash"] == "11 (sha256)")
    assert(pcr_select["sizeofSelect"] == 3)
    assert(pcr_select["pcrSelect"] == "151e02")

    # pcrDigest should be lowercase hex encoded sha256sum per above options
    assert(re.match('^[0-9a-f]{64}$', quote["pcrDigest"]))

    print("OK")
pyscript

exit 0
