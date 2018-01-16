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

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    if [ -e "$PRINT_TEMP_FILE" ]; then
        cat "$PRINT_TEMP_FILE"
        rm "$PRINT_TEMP_FILE"
    fi
    exit 1
}
trap onerror ERR

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
PRINT_TEMP_FILE=$(mktemp --suffix=-tpm2_print)

for expectedFile in "$SCRIPT_DIR/print-files/"*.printed; do
    testFileBasename=${expectedFile::-8}

    if [ -e "$testFileBasename.TPMS_ATTEST" ]; then
        tpm2_print --type=TPMS_ATTEST --file="$testFileBasename.TPMS_ATTEST" >"$PRINT_TEMP_FILE" 2>&1
        diff "$PRINT_TEMP_FILE" "$expectedFile"

        tpm2_print -t TPMS_ATTEST -f "$testFileBasename.TPMS_ATTEST" >"$PRINT_TEMP_FILE" 2>&1
        diff "$PRINT_TEMP_FILE" "$expectedFile"
    else
        echo 1>&2 "Could not find input file"
        exit 1
    fi
done

rm "$PRINT_TEMP_FILE"
exit 0
