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

cleanup() {
    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

aesmodes="$(populate_algs "details['encrypting'] and details['symmetric']")"
hashalgs="$(populate_algs "details['hash'] and not details['method'] \
                                           and not details['signing'] \
                                           and not details['symmetric'] \
                                           and alg is not None")"
eccmethods="$(populate_algs "details['signing'] and not details['hash'] and \"rsa\" not in alg")"
rsamethods="$(populate_algs "details['signing'] and not details['hash'] and \"ec\" not in alg")"

# Test that common algorithms are supported
for i in "rsa" "xor" "hmac" "ecc" "keyedhash"; do
    tpm2_testparms "${i}"
done

# Test that RSA signing schemes are supported
for i in ${rsamethods}; do
    tpm2_testparms "rsa:${i}"
done

# Test that ECC signing schemes are supported
for i in ${eccmethods}; do
    tpm2_testparms "ecc:${i}"
done

# Test that aes modes are supported
for i in ${aesmodes}; do
    tpm2_testparms "aes128${i}"
done

# Test that xor on hash algs is supported
for i in ${hashalgs}; do
    tpm2_testparms "xor:${i}"
done

# Test that hmac on hash algs is supported
for i in ${hashalgs}; do
    tpm2_testparms "hmac:${i}"
done

# Test that null algorithm raise an error (error from software stack)
if ! tpm2_testparms "null" 2>&1 1>/dev/null | grep -q "Invalid or unsupported by the tool : null"; then
    echo "tpm2_testparms with 'null' algorithm didn't fail"
    exit 1
else
    true
fi

# Attempt to specify a suite that is not supported (error from TPM)
if tpm2_testparms "ecc521:ecdsa:aes256cbc" &>/dev/null; then
    echo "tpm2_testparms succeeded while it shouldn't or TPM failed"
    exit 1
else
    true
fi
exit 0
