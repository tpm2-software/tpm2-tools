#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
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

file_primary_key_ctx=context.p_B1
file_signing_key_pub=opuB1_B8
file_signing_key_priv=oprB1_B8
file_signing_key_ctx=context_load_out_B1_B8
file_signing_key_name=name.load.B1_B8
file_input_data=secret.data
file_input_digest=secret.digest
file_output_data=sig.4
file_output_ticket=secret.ticket
file_output_hash=secret.hash

handle_signing_key=0x81010005

alg_hash=sha256
alg_primary_key=0x0001
alg_signing_key=hmac

cleanup() {
    rm -f $file_input_data $file_primary_key_ctx $file_signing_key_pub \
          $file_signing_key_priv $file_signing_key_ctx $file_signing_key_name \
          $file_output_data $file_input_digest $file_output_ticket \
          $file_output_hash

    tpm2_evictcontrol -Q -ao -c $handle_signing_key 2>/dev/null || true

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo "12345678" > $file_input_data

tpm2_clear

tpm2_createprimary -Q -a e -g $alg_hash -G $alg_primary_key -o $file_primary_key_ctx

tpm2_create -Q -g $alg_hash -G $alg_signing_key -u $file_signing_key_pub -r $file_signing_key_priv  -C $file_primary_key_ctx

tpm2_load -Q -C $file_primary_key_ctx  -u $file_signing_key_pub  -r $file_signing_key_priv -n $file_signing_key_name -o $file_signing_key_ctx

tpm2_sign -Q -c $file_signing_key_ctx -G $alg_hash -m $file_input_data -s $file_output_data

rm -f $file_output_data

tpm2_evictcontrol -Q -a o -c $file_signing_key_ctx -p $handle_signing_key

tpm2_sign -Q -c $handle_signing_key -G $alg_hash -m $file_input_data -s $file_output_data

rm -f $file_output_data

# generate hash and test validation

tpm2_hash -Q -a e -G $alg_hash -o $file_output_hash -t $file_output_ticket $file_input_data

tpm2_sign -Q -c $handle_signing_key -G $alg_hash -s $file_output_data -m $file_input_data -t $file_output_ticket

rm -f $file_output_data

# test with digest, no validation

sha256sum $file_input_data | awk '{ print "000000 " $1 }' | xxd -r -c 32 > $file_input_digest

tpm2_sign -Q -c $handle_signing_key -G $alg_hash -D $file_input_digest -s $file_output_data

rm -f $file_output_data

# test with digest + message/validation (warning generated)

tpm2_sign -Q -c $handle_signing_key -G $alg_hash -D $file_input_digest -s $file_output_data -m $file_input_data -t $file_output_ticket |& grep -q ^WARN

exit 0
