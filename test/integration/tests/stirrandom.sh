#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2019, Sebastien LE STUM
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

goodfile=$(mktemp)
bigfile=$(mktemp)
{
    dd if=/dev/urandom of="${bigfile}" bs=1 count=256
    dd if=/dev/urandom of="${goodfile}" bs=1 count=42
} &>/dev/null

cleanup() {
    if [ "$1" != "no-shut-down" ]; then
        shut_down
        rm -f "${bigfile}"
        rm -f "${goodfile}"
    fi
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

# Sending bytes from stdin (pipe)
echo -n "return 4" | tpm2_stirrandom -V 2>&1 1>/dev/null | grep -q "Submitting 8 bytes to TPM"

# Sending bytes from stdin (file)
tpm2_stirrandom -V < "${goodfile}" 2>&1 1>/dev/null | grep -q "Submitting 42 bytes to TPM"

# Read more than 128 bytes from stdin (pipe)
dd if=/dev/urandom bs=1 count=256 | tpm2_stirrandom -V 2>&1 1>/dev/null | grep -q "Submitting 128 bytes to TPM"

# Read more than 128 bytes from stdin (file)
dd if=/dev/urandom bs=1 count=256 | tpm2_stirrandom -V < "${bigfile}" 2>&1 1>/dev/null | grep -q "Submitting 128 bytes to TPM"

# Read a complete file
tpm2_stirrandom "${goodfile}" -V 2>&1 1>/dev/null | grep -q "Submitting 42 bytes to TPM"

# Try to read more than 128 bytes from file and get an error
if tpm2_stirrandom "${bigfile}"; then
    echo "tpm2_stirrandom didn't fail on exceeding requested size"
    exit 1
else
    true
fi

exit 0