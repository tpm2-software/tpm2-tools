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

handle_ek=0x81010007
handle_ak=0x81010008
handle_nv=0x1500018
handle_hier=0x40000001
ek_alg=rsa
ak_alg=rsa
digestAlg=sha256
signAlg=rsassa
ownerpw=ownerpass
endorsepw=endorsepass
ekpw=ekpass
akpw=akpass

file_input_data=secret.data
file_input_key=nv.data
output_ek_pub_pem=ekpub.pem
output_ek_pub=ek.pub
output_ak_pub_pem=akpub.pem
output_ak_pub=ak.pub
output_ak_priv=ak.priv
output_ak_pub_name=ak.name
output_mkcredential=mkcred.out
output_actcredential=actcred.out
output_quote=quote.out
output_quotesig=quotesig.out
output_quotepcr=quotepcr.out

cleanup() {
  rm -f $output_ak_priv \
        $file_input_data $file_input_key $output_ek_pub $output_ek_pub_pem $output_ak_pub \
        $output_ak_pub_pem $output_ak_pub_name $output_mkcredential \
        $output_actcredential $output_quote $output_quotesig $output_quotepcr rand.out 

  tpm2_pcrreset 16
  tpm2_evictcontrol -Q -Ao -c $handle_ek 2>/dev/null || true
  tpm2_evictcontrol -Q -Ao -c $handle_ak 2>/dev/null || true

  tpm2_nvrelease -Q -x $handle_nv -a $handle_hier -P "$ownerpw" 2>/dev/null || true

  tpm2_takeownership -c 2>/dev/null || true
}
trap cleanup EXIT


cleanup

echo "12345678" > $file_input_data
echo "1234567890123456789012345678901" > $file_input_key

getrandom() {
  tpm2_getrandom -Q -o rand.out $1
  local file_size=`stat --printf="%s" rand.out`
  loaded_randomness=`cat rand.out | xxd -p -c $file_size`
}


tpm2_takeownership -o "$ownerpw" -e "$endorsepw"

# Key generation
tpm2_getpubek -Q -H $handle_ek -g $ek_alg -f $output_ek_pub -P "$ekpw" -o "$ownerpw" -e "$endorsepw"
tpm2_readpublic -Q -H $handle_ek -o $output_ek_pub_pem -f pem
tpm2_getpubak -Q -E $handle_ek -k $handle_ak -g $ak_alg -D $digestAlg -s $signAlg -f $output_ak_pub -n $output_ak_pub_name -e "$endorsepw" -P "$akpw" -o "$ownerpw"
tpm2_readpublic -Q -H $handle_ak -o $output_ak_pub_pem -f pem

# Validate keys (registrar)
file_size=`stat --printf="%s" $output_ak_pub_name`
loaded_key_name=`cat $output_ak_pub_name | xxd -p -c $file_size`
tpm2_makecredential -Q -T none -e $output_ek_pub  -s $file_input_data -n $loaded_key_name -o $output_mkcredential 
tpm2_activatecredential -Q -H $handle_ak -k $handle_ek -f $output_mkcredential -o $output_actcredential -P "$akpw" -e "$endorsepw"
diff $file_input_data $output_actcredential


# Quoting
tpm2_pcrreset -Q 16
tpm2_pcrextend -Q 16:sha256=6ea40aa7267bb71251c1de1c3605a3df759b86b22fa9f62aa298d4197cd88a38
tpm2_pcrlist -Q
getrandom 20
tpm2_quote -Q -k $handle_ak -L $digestAlg:15,16,22 -q $loaded_randomness -m $output_quote -s $output_quotesig -p $output_quotepcr -G $digestAlg -P "$akpw"


# Verify quote
tpm2_checkquote -Q -c $output_ak_pub_pem -m $output_quote -s $output_quotesig -p $output_quotepcr -G $digestAlg -q $loaded_randomness


# Save U key from verifier
tpm2_nvdefine -Q -x $handle_nv -a $handle_hier -s 32 -t "ownerread|policywrite|ownerwrite" -I "indexpass" -P "$ownerpw"
tpm2_nvwrite -Q -x $handle_nv -a $handle_hier -P "$ownerpw" $file_input_key
tpm2_nvread -Q -x $handle_nv -a $handle_hier -s 32 -P "$ownerpw"

exit 0
