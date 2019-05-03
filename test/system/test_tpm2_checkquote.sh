#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2019 Massachusetts Institute of Technology.
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
alg_create_obj=sha256
alg_create_key=rsa

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_quote_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_quote_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_quote_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_quote_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
output_ak_pub_pem=akpub.pem
output_quote=quote.out
output_quotesig=quotesig.out
output_quotepcr=quotepcr.out

maxdigest=$(tpm2_getcap -c properties-fixed | grep TPM_PT_MAX_DIGEST | sed -r -e 's/.*(0x[0-9a-f]+)/\1/g')
if ! [[ "$maxdigest" =~ ^(0x)*[0-9]+$ ]] ; then
 echo "error: not a number, got: \"$maxdigest\"" >&2
 exit 1
fi

nonce=12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde
nonce=${nonce:0:2*$maxdigest}

cleanup() {
  rm -f $file_primary_key_ctx $file_quote_key_pub $file_quote_key_priv \
        $file_quote_key_name $file_quote_key_ctx $output_ak_pub_pem \
        $output_quote $output_quotesig $output_quotepcr
}
trap cleanup EXIT

cleanup


tpm2_takeownership -c

# Key generation
tpm2_createprimary -Q -H e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx
tpm2_create -Q -g $alg_create_obj -G $alg_create_key -u $file_quote_key_pub -r $file_quote_key_priv  -c $file_primary_key_ctx
tpm2_load -Q -c $file_primary_key_ctx  -u $file_quote_key_pub  -r $file_quote_key_priv -n $file_quote_key_name -C $file_quote_key_ctx

# Get the PEM version of pub ak cert
tpm2_readpublic -Q -c $file_quote_key_ctx -o $output_ak_pub_pem -f pem

# Quoting
tpm2_quote -Q -c $file_quote_key_ctx  -L sha256:15,16,22 -q $nonce -m $output_quote -s $output_quotesig -p $output_quotepcr -G $alg_primary_obj

# Verify quote
tpm2_checkquote -Q -c $output_ak_pub_pem -m $output_quote -s $output_quotesig -p $output_quotepcr -G $alg_primary_obj -q $nonce

exit 0
