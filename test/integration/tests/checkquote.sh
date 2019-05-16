#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

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
ak_ctx=ak.ctx

output_ek_pub_pem=ekpub.pem
output_ak_pub_pem=akpub.pem
output_ak_pub_name=ak.name
output_quote=quote.out
output_quotesig=quotesig.out
output_quotepcr=quotepcr.out

cleanup() {
  rm -f $output_ek_pub_pem \
        $output_ak_pub_pem $output_ak_pub_name \
        $output_quote $output_quotesig $output_quotepcr rand.out \
	    $ak_ctx

  tpm2_pcrreset 16
  tpm2_evictcontrol -a o -c $handle_ek -P "$ownerpw" 2>/dev/null || true
  tpm2_evictcontrol -a o -c $handle_ak -P "$ownerpw" 2>/dev/null || true

  tpm2_changeauth -W "$ownerpw" -E "$endorsepw" 2>/dev/null || true

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

tpm2_createak -C $handle_ek -c $ak_ctx -G $ak_alg -D $digestAlg -s $signAlg -p $output_ak_pub_pem -f pem -n $output_ak_pub_name -P "$akpw"
tpm2_evictcontrol -Q -c $ak_ctx -p $handle_ak

# Quoting
getrandom 20
tpm2_quote -C $handle_ak -L sha256:15,16,22 -q $loaded_randomness -m $output_quote -s $output_quotesig -p $output_quotepcr -g $digestAlg -P "$akpw"

# Verify quote
tpm2_checkquote -u $output_ak_pub_pem -m $output_quote -s $output_quotesig -F $output_quotepcr -g $digestAlg -q $loaded_randomness

exit 0
