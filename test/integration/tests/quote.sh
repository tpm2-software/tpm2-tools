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

alg_primary_obj=sha256
alg_primary_key=rsa
alg_create_obj=0x000B
alg_create_key=hmac

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

out=out.yaml
toss_out=junk.out

cleanup() {
    rm -f $file_primary_key_ctx $file_quote_key_pub $file_quote_key_priv \
    $file_quote_key_name $file_quote_key_ctx ek.pub2 ak.pub2 ak.name_2 \
    $out $toss_out

    tpm2_evictcontrol -Q -ao -c $Handle_ek_quote 2>/dev/null || true
    tpm2_evictcontrol -Q -ao -c $Handle_ak_quote 2>/dev/null || true
    tpm2_evictcontrol -Q -ao -c $Handle_ak_quote2 2>/dev/null || true

    if [ "$1" != "no-shut-down" ]; then
       shut_down
    fi
}
trap cleanup EXIT

start_up

tpm2_getcap -c properties-fixed | tr -dc '[[:print:]]\r\n' > $out
maxdigest=$(yaml_get_kv $out \"TPM2_PT_MAX_DIGEST\" \"value\")
if ! [[ "$maxdigest" =~ ^(0x)*[0-9]+$ ]] ; then
 echo "error: not a number, got: \"$maxdigest\"" >&2
 exit 1
fi

nonce=12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde
nonce=${nonce:0:2*$maxdigest}

cleanup "no-shut-down"

tpm2_clear

tpm2_createprimary -Q -a e -g $alg_primary_obj -G $alg_primary_key -o $file_primary_key_ctx

tpm2_create -Q -g $alg_create_obj -G $alg_create_key -u $file_quote_key_pub -r $file_quote_key_priv  -C $file_primary_key_ctx

tpm2_load -Q -C $file_primary_key_ctx  -u $file_quote_key_pub  -r $file_quote_key_priv -n $file_quote_key_name -o $file_quote_key_ctx

tpm2_quote -C $file_quote_key_ctx  -L $alg_quote:16,17,18 -q $nonce -m $toss_out -s $toss_out -p $toss_out -G $alg_primary_obj > $out

yaml_verify $out

tpm2_quote -Q -C $file_quote_key_ctx  -L $alg_quote:16,17,18+$alg_quote1:16,17,18 -q $nonce -m $toss_out -s $toss_out -p $toss_out -G $alg_primary_obj

#####handle testing
tpm2_evictcontrol -Q -a o -c $file_quote_key_ctx -p $Handle_ak_quote

tpm2_quote -Q -C $Handle_ak_quote -L $alg_quote:16,17,18 -q $nonce -m $toss_out -s $toss_out -p $toss_out -G $alg_primary_obj

tpm2_quote -Q -C $Handle_ak_quote  -L $alg_quote:16,17,18+$alg_quote1:16,17,18 -q $nonce -m $toss_out -s $toss_out -p $toss_out -G $alg_primary_obj

#####AK
tpm2_createek -Q -c $Handle_ek_quote -G 0x01 -p ek.pub2

tpm2_createak -Q -C $Handle_ek_quote -k  $Handle_ak_quote2 -p ak.pub2 -n ak.name_2

tpm2_quote -Q -C $Handle_ak_quote -L $alg_quote:16,17,18 -l 16,17,18 -q $nonce -m $toss_out -s $toss_out -p $toss_out -G $alg_primary_obj

exit 0
