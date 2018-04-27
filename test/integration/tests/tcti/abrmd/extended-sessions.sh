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

alg_primary_obj=sha256
alg_primary_key=ecc
alg_create_obj=sha256
alg_create_key=keyedhash
alg_pcr_policy=sha1

pcr_ids="0,1,2,3"

file_pcr_value=pcr.bin
file_input_data=secret.data
file_policy=policy.data
file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_unseal_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_unseal_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_unseal_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_unseal_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_unseal_output_data=usl_"$file_unseal_key_ctx"
file_session_file="session.dat"

secret="12345678"

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

cleanup() {
  rm -f $file_input_data $file_primary_key_ctx $file_unseal_key_pub \
        $file_unseal_key_priv $file_unseal_key_ctx $file_unseal_key_name \
        $file_unseal_output_data $file_pcr_value \
        $file_policy $file_session_file

  tpm2_flushcontext -S $file_session_file 2>/dev/null || true
}
trap cleanup EXIT

start_up

cleanup

echo $secret > $file_input_data

tpm2_clear

#
# Test an extended policy session beyond client connections. This is ONLY supported by abrmd
# since version: https://github.com/tpm2-software/tpm2-abrmd/releases/tag/1.2.0
# However, bug: https://github.com/tpm2-software/tpm2-abrmd/issues/285 applies
#
# The test works by:
# Step 1: Creating a trial session and updating it with a policyPCR event to generate
#   a policy hash.
#
# Step 2: Creating an object and using that policy hash as the policy to satisfy for usage.
#
# Step 3: Creating an actual policy session and using pcrpolicy event to update the policy.
#
# Step 4: Using that actual policy session from step 3 in tpm2_unseal to unseal the object.
#

tpm2_createprimary -Q -a e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx

tpm2_pcrlist -Q -L ${alg_pcr_policy}:${pcr_ids} -o $file_pcr_value

tpm2_startauthsession -Q -S $file_session_file

tpm2_policypcr -Q -S $file_session_file -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value -f $file_policy

tpm2_flushcontext -S $file_session_file

tpm2_create -Q -g $alg_create_obj -G $alg_create_key -u $file_unseal_key_pub -r $file_unseal_key_priv -I- -c $file_primary_key_ctx -L $file_policy \
  -A 'sign|fixedtpm|fixedparent|sensitivedataorigin' <<< $secret

tpm2_load -Q -c $file_primary_key_ctx -u $file_unseal_key_pub -r $file_unseal_key_priv -n $file_unseal_key_name -C $file_unseal_key_ctx

# Start a REAL policy session (-a option) and perform a pcr policy event
handle=`tpm2_startauthsession -a -S $file_session_file | cut -d' ' -f 2-2`

tpm2_policypcr -Q -S $file_session_file -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value -f $file_policy

unsealed=`tpm2_unseal -P"session:$file_session_file" -c $file_unseal_key_ctx`

test "$unsealed" == "$secret"

# Test resetting the policy session causes unseal to fail.
tpm2_policyrestart -S $file_session_file

# negative test, clear the error handler
trap - ERR

tpm2_unseal -P"session:$file_session_file" -c $file_unseal_key_ctx 2>/dev/null
rc=$?

# restore the error handler
trap onerror ERR
if [ $rc -eq 0 ]; then
  echo "Expected tpm2_unseal to fail after policy reset"
  false
fi

exit 0
