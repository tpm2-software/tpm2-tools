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
alg_primary_obj=0x000B
alg_primary_key=0x0001
alg_create_obj=0x000B
alg_create_key=0x0008
halg=0x000B

handle_hmac_key=0x81010013

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_hmac_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_hmac_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_hmac_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_hmac_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_hmac_output=hmac_"$file_hmac_key_ctx"

file_input_data=secret.data

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

cleanup() {
  rm -f $file_primary_key_ctx $file_hmac_key_pub $file_hmac_key_priv \
        $file_hmac_key_name $file_hmac_output evict.log
  if [ "$1" == "all" ]; then
    rm -f $file_hmac_key_ctx $file_input_data
  fi
}

onexit() {
  cleanup "all"
}
trap onexit EXIT

cleanup

echo "12345678" > $file_input_data

tpm2_takeownership -c

tpm2_createprimary -Q -H e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx

tpm2_create -Q -g $alg_create_obj -G $alg_create_key -u $file_hmac_key_pub -r $file_hmac_key_priv  -c $file_primary_key_ctx

tpm2_load -Q -c $file_primary_key_ctx  -u $file_hmac_key_pub  -r $file_hmac_key_priv -n $file_hmac_key_name -C $file_hmac_key_ctx

cat $file_input_data | tpm2_hmac -Q -c $file_hmac_key_ctx  -g $halg -o $file_hmac_output

cleanup

# Test large file, ie sequence hmac'ing.
dd if=/dev/urandom of=$file_input_data bs=2093 count=1 2>/dev/null
tpm2_hmac -Q -c $file_hmac_key_ctx -g $halg -o $file_hmac_output $file_input_data

####handle test
rm -f $file_hmac_output  

tpm2_evictcontrol -A o -c $file_hmac_key_ctx -S $handle_hmac_key > evict.log
grep -q "persistentHandle: "$handle_hmac_key"" evict.log

echo "12345678" > $file_input_data
tpm2_hmac -Q -k $handle_hmac_key  -g $halg -o $file_hmac_output $file_input_data

cleanup all

# Test default algorithm selection of sha1
echo "12345678" > $file_input_data

tpm2_takeownership -c

tpm2_createprimary -Q -H e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx

tpm2_create -Q -g sha1 -G $alg_create_key -u $file_hmac_key_pub -r $file_hmac_key_priv  -c $file_primary_key_ctx

tpm2_load -Q -c $file_primary_key_ctx  -u $file_hmac_key_pub  -r $file_hmac_key_priv -n $file_hmac_key_name -C $file_hmac_key_ctx

cat $file_input_data | tpm2_hmac -Q -c $file_hmac_key_ctx -o $file_hmac_output

# test no output file
cat $file_input_data | tpm2_hmac -c $file_hmac_key_ctx 1>/dev/null

# test no output file with halg
cat $file_input_data | tpm2_hmac -g sha1 -c $file_hmac_key_ctx 1>/dev/null

# verify that silent is indeed silent
stdout=`cat $file_input_data | tpm2_hmac -Q -g sha1 -c $file_hmac_key_ctx`
if [ -n "$stdout" ]; then
    echo "Expected no output when run in quiet mode, got\"$stdout\""
    exit 1
fi

exit 0
