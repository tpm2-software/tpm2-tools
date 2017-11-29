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

cleanup() {
  rm -f primary.ctx decrypt.ctx key.pub key.priv key.name decrypt.out \
        encrypt.out secret.dat &>/dev/null
}
trap cleanup EXIT

cleanup

# Check for encryptdecrypt command code 0x164
tpm2_getcap -c commands | grep -q 0x164
if [ $? != 0 ];then
    echo "WARN: Command EncryptDecrypt is not supported by your device, skipping..."
    exit 0
fi

# Now set the trap handler for ERR since we're past the command code check
trap onerror ERR

echo "12345678" > secret.dat

tpm2_takeownership -Q -c

tpm2_createprimary -Q -H e -g sha1 -G rsa -C primary.ctx

tpm2_create -Q -g sha256 -G symcipher -u key.pub -r key.priv -c primary.ctx

tpm2_load -Q -c primary.ctx -u key.pub -r key.priv -n key.name -C decrypt.ctx

tpm2_encryptdecrypt -Q -c decrypt.ctx  -I secret.dat -o encrypt.out

tpm2_encryptdecrypt -Q -c  decrypt.ctx -D -I encrypt.out -o decrypt.out

exit 0

