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

TPM_CC_UNSEAL=0x15E
file_primary_key_ctx=prim.ctx
file_input_data=secret.data
file_policy=policy.data
file_unseal_key_pub=sealkey.pub
file_unseal_key_priv=sealkey.priv
file_unseal_key_ctx=sealkey.ctx
file_unseal_key_name=sealkey.name
file_output_data=unsealed.data
file_session_data=session.dat

secret="12345678"

cleanup() {
    rm -f  $file_primary_key_ctx $file_input_data $file_policy $file_unseal_key_pub\
    $file_unseal_key_priv $file_unseal_key_ctx $file_unseal_key_name\
    $file_output_data $file_session_data

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

echo $secret > $file_input_data

tpm2_clear

tpm2_createprimary -Q -a o -o $file_primary_key_ctx

TPM_CC_UNSEAL=0x15E

tpm2_startauthsession -S $file_session_data

tpm2_policycommandcode -S $file_session_data -o $file_policy $TPM_CC_UNSEAL

tpm2_flushcontext -S $file_session_data

rm $file_session_data

tpm2_create -C $file_primary_key_ctx -u $file_unseal_key_pub \
  -r $file_unseal_key_priv -L $file_policy -i- <<< $secret

tpm2_load -C $file_primary_key_ctx -u $file_unseal_key_pub \
  -r $file_unseal_key_priv -n $file_unseal_key_name -o $file_unseal_key_ctx


# Ensure unsealing passes with proper policy
tpm2_startauthsession --policy-session -S $file_session_data

tpm2_policycommandcode -S $file_session_data -o $file_policy $TPM_CC_UNSEAL

tpm2_unseal -p session:$file_session_data -c sealkey.ctx > $file_output_data

tpm2_flushcontext -S $file_session_data

rm $file_session_data

cmp -s $file_output_data $file_input_data

# Test that other operations fail
if tpm2_encryptdecrypt -i $file_input_data -o $file_output_data -c $file_unseal_key_ctx; then
    echo "tpm2_policycommandcode: Should have failed!"
    exit 1
else
    true
fi

exit 0
