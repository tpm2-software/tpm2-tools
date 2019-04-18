#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2018, National Instruments
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

ak_handle=0x81010016
ek_handle=0x81010017

ak_name_file=ak.name
ak_pubkey_file=ak.pub
ek_pubkey_file=ek.pub

quote_file=quote.bin
print_file=quote.yaml

cleanup() {
    rm -f $ak_name_file $ak_pubkey_file $ek_pubkey_file \
          $quote_file $print_file

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
tpm2_createak -Q -G rsa -D sha256 -s rsassa -C $ek_handle -k $ak_handle -p $ak_pubkey_file -n $ak_name_file

# Take PCR quote
tpm2_quote -Q -C $ak_handle -L "sha256:0,2,4,9,10,11,12,17" -q "0f8beb45ac" -m $quote_file

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
