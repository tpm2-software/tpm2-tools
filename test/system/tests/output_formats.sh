#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2017, SUSE Linux GmbH
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

# Purpose of this test is to cover the additional code paths that come into
# play when non-default output formats for public keys or signatures are used
# in the various tools.
#
# The test covers all available output formats, makes sure the tools
# successfully run in these cases and checks the output files by feeding them
# to OpenSSL as appropriate.

alg_ek=rsa
file_pubek_base=ek_${alg_ek}
file_pubek_orig=${file_pubek_base}.tss.orig
handle_ek=0x81010014

alg_ak=rsa
file_pubak_name="ak.${alg_ak}.name"
file_pubak_tss="ak.${alg_ak}.tss"
file_pubak_pem="ak.${alg_ak}.pem"
handle_ak=0x81010016

file_hash_input="$0"
file_hash_ticket=hash.ticket
file_hash_result=hash.result
file_sig_base=hash.sig
alg_hash=sha256

file_quote_msg=quote.msg
file_quote_sig_base=quote.sig

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

cleanup() {
    rm -f "$file_pubek_base".*
    rm -f "$file_pubak_tss" "$file_pubak_name" "$file_pubak_pem"
    rm -f "$file_hash_ticket" "$file_hash_result" "$file_sig_base".*
    rm -f "$file_quote_msg" "$file_quote_sig_base".*

    # Evict persistent handles, we want them to always succeed and never trip
    # the onerror trap.
    for handle in $handle_ek $handle_ak; do
        tpm2_evictcontrol -Q -A o -H $handle 2>/dev/null || true
    done
}
trap cleanup EXIT

tpm2_takeownership -c

tpm2_getpubek -Q -g $alg_ek -f "$file_pubek_orig" -H $handle_ek

for fmt in tss pem der; do

    this_key="${file_pubek_base}.${fmt}"

    tpm2_readpublic -Q -H $handle_ek -f "$fmt" -o "$this_key"

    if [ "$fmt" = tss ]; then
        diff "$file_pubek_orig" "$this_key" > /dev/null
    else
        openssl rsa -pubin -inform "$fmt" -text -in "$this_key" &> /dev/null
    fi

done

tpm2_getpubak -Q -g $alg_ak -E $handle_ek -k $handle_ak -f "$file_pubak_tss" -n "$file_pubak_name"

tpm2_readpublic -Q -H $handle_ak -f "pem" -o "$file_pubak_pem"

tpm2_hash -Q -H e -g $alg_hash -t "$file_hash_ticket" -o "$file_hash_result" "$file_hash_input"

for fmt in tss plain; do
    this_sig="${file_sig_base}.${fmt}"
    tpm2_sign -Q -k $handle_ak -g $alg_hash -m "${file_hash_input}" -f $fmt -s "${this_sig}" -t "${file_hash_ticket}"

    if [ "$fmt" = plain ]; then
        openssl dgst -verify "$file_pubak_pem" -keyform pem -${alg_hash} -signature "$this_sig" "$file_hash_input" > /dev/null
    fi
done

for fmt in tss plain; do
    this_sig="${file_quote_sig_base}.${fmt}"
    tpm2_quote -Q -k $handle_ak -l 0 -g "$alg_hash" -f $fmt -m "$file_quote_msg" -s "$this_sig"

    if [ "$fmt" = plain ]; then
        openssl dgst -verify "$file_pubak_pem" -keyform pem -${alg_hash} -signature "$this_sig" "$file_quote_msg" > /dev/null
    fi
done

exit 0
