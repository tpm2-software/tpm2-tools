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

alg_primary_obj=sha256
alg_primary_key=rsa
alg_create_obj=0x000B
alg_create_key=0x0008

alg_quote=0x0004
alg_quote1=0x000b

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_quote_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_quote_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_quote_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_quote_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"

Handle_ak_quote=0x81010016
Handle_ek_quote=0x81010017
Handle_ak_quote2=0x81010018
Handle_ak_quote3=0x81010019

maxdigest=$(tpm2_getcap -c properties-fixed | grep TPM_PT_MAX_DIGEST | sed -r -e 's/.*(0x[0-9a-f]+)/\1/g')
if ! [[ "$maxdigest" =~ ^(0x)*[0-9]+$ ]] ; then
 echo "error: not a number, got: \"$maxdigest\"" >&2
 exit 1
fi

nonce=12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde
nonce=${nonce:0:2*$maxdigest}

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

cleanup() {
    rm -f $file_primary_key_ctx $file_quote_key_pub $file_quote_key_priv \
    $file_quote_key_name $file_quote_key_ctx ek.pub2 ak.pub2 ak.name_2 \

    tpm2_evictcontrol -Q -Ao -H $Handle_ek_quote 2>/dev/null || true
    tpm2_evictcontrol -Q -Ao -H $Handle_ak_quote 2>/dev/null || true
    tpm2_evictcontrol -Q -Ao -H $Handle_ak_quote2 2>/dev/null || true
    tpm2_evictcontrol -Q -Ao -H $Handle_ak_quote3 2>/dev/null || true
}
trap cleanup EXIT

cleanup

tpm2_takeownership -c

tpm2_createprimary -Q -H e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx

tpm2_create -Q -g $alg_create_obj -G $alg_create_key -u $file_quote_key_pub -r $file_quote_key_priv  -c $file_primary_key_ctx

tpm2_load -Q -c $file_primary_key_ctx  -u $file_quote_key_pub  -r $file_quote_key_priv -n $file_quote_key_name -C $file_quote_key_ctx

tpm2_quote -Q -c $file_quote_key_ctx  -g $alg_quote -l 16,17,18 -q $nonce

tpm2_quote -Q -c $file_quote_key_ctx  -L $alg_quote:16,17,18+$alg_quote1:16,17,18 -q $nonce

#####handle testing
tpm2_evictcontrol -Q -A o -c $file_quote_key_ctx -S $Handle_ak_quote

tpm2_quote -Q -k $Handle_ak_quote  -g $alg_quote -l 16,17,18 -q $nonce

tpm2_quote -Q -k $Handle_ak_quote  -L $alg_quote:16,17,18+$alg_quote1:16,17,18 -q $nonce

#####AK
tpm2_getpubek -Q -H  $Handle_ek_quote -g 0x01 -f ek.pub2

tpm2_getpubak -Q -E  $Handle_ek_quote -k  $Handle_ak_quote2 -f ak.pub2 -n ak.name_2

tpm2_quote -Q -k $Handle_ak_quote -g $alg_quote -l 16,17,18 -q $nonce

#####AK with password
tpm2_getpubak -Q -E  $Handle_ek_quote -k  $Handle_ak_quote3 -f ak.pub2 -n ak.name_2 -P abc123

tpm2_quote -Q -k $Handle_ak_quote3 -g $alg_quote -l 16,17,18 -q $nonce -P abc123

exit 0