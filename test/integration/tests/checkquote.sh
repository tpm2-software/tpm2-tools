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

source helpers.sh

handle_ek=0x81010009
handle_ak=0x8101000a
ek_alg=rsa
ak_alg=rsa
digestAlg=sha256
signAlg=rsassa
ownerpw=ownerpass
endorsepw=endorsepass
ekpw=ekpass
akpw=akpass

output_ek_pub_pem=ekpub.pem
output_ak_pub_pem=akpub.pem
output_ak_pub_name=ak.name
output_quote=quote.out
output_quotesig=quotesig.out
output_quotepcr=quotepcr.out

cleanup() {
  rm -f $output_ek_pub_pem \
        $output_ak_pub_pem $output_ak_pub_name \
        $output_quote $output_quotesig $output_quotepcr rand.out 

  tpm2_pcrreset 16
  tpm2_evictcontrol -a o -c $handle_ek -P "$ownerpw" 2>/dev/null || true
  tpm2_evictcontrol -a o -c $handle_ak -P "$ownerpw" 2>/dev/null || true

  tpm2_changeauth -O "$ownerpw" -E "$endorsepw" 2>/dev/null || true

  ina "$@" "no-shut-down"
  if [ $? -ne 0 ]; then
    shut_down
    echo "shutdown"
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

getrandom() {
  tpm2_getrandom -o rand.out $1
  local file_size=`stat --printf="%s" rand.out`
  loaded_randomness=`cat rand.out | xxd -p -c $file_size`
}

# Key generation
tpm2_createek -c $handle_ek -G $ek_alg -p $output_ek_pub_pem -f pem -P "$ekpw"

tpm2_createak -C $handle_ek -k $handle_ak -G $ak_alg -D $digestAlg -s $signAlg -p $output_ak_pub_pem -f pem -n $output_ak_pub_name -P "$akpw"

# Quoting
getrandom 20
tpm2_quote -C $handle_ak -L sha256:15,16,22 -q $loaded_randomness -m $output_quote -s $output_quotesig -p $output_quotepcr -g $digestAlg -P "$akpw"

# Verify quote
tpm2_checkquote -u $output_ak_pub_pem -m $output_quote -s $output_quotesig -F $output_quotepcr -g $digestAlg -q $loaded_randomness

exit 0

