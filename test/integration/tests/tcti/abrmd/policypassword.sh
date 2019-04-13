#!/bin/bash
#;**********************************************************************;
#
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

policypassword=policy.dat
session_ctx=session.ctx
o_policy_digest=policy.digest
primary_key_ctx=prim.ctx
key_ctx=key.ctx
key_pub=key.pub
key_priv=key.priv
plain_txt=plain.txt
encrypted_txt=enc.txt
decrypted_txt=dec.txt
testpswd=testpswd

cleanup() {
    rm -f  $policypassword $session_ctx $o_policy_digest $primary_key_ctx $key_ctx\
    $key_pub $key_priv $plain_txt $encrypted_txt $decrypted_txt

    tpm2_flushcontext -S $session_ctx 2>/dev/null || true

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

echo "plaintext" > $plain_txt

tpm2_startauthsession -S $session_ctx
tpm2_policypassword -S $session_ctx -o $policypassword
tpm2_flushcontext -S $session_ctx
rm $session_ctx

tpm2_createprimary -a o -o $primary_key_ctx

tpm2_create -g sha256 -G aes -u $key_pub -r $key_priv -C $primary_key_ctx \
  -L $policypassword -p $testpswd

tpm2_load -C $primary_key_ctx -u $key_pub -r $key_priv -o $key_ctx
tpm2_encryptdecrypt -c $key_ctx -o $encrypted_txt -i $plain_txt -p $testpswd

tpm2_startauthsession -a -S $session_ctx
tpm2_policypassword -S $session_ctx -o $policypassword
tpm2_encryptdecrypt -c $key_ctx -i $encrypted_txt -o $decrypted_txt -D \
  -p session:$session_ctx+$testpswd
tpm2_flushcontext -S $session_ctx
rm $session_ctx

diff $plain_txt $decrypted_txt

exit 0
