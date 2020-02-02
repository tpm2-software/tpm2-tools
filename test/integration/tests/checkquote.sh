# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

handle_ek=0x81010009
handle_ak=0x8101000a
ek_alg=rsa
ak_alg=rsa
digestAlg=sha256
signAlg=rsassa
akpw=akpass
ak_ctx=ak.ctx

output_ek_pub_pem=ekpub.pem
output_ak_pub_pem=akpub.pem
output_ak_pub_name=ak.name
output_quote=quote.out
output_quotesig=quotesig.out
output_quotepcr=quotepcr.out

cleanup() {
  rm -f $output_ek_pub_pem $output_ak_pub_pem $output_ak_pub_name \
  $output_quote $output_quotesig $output_quotepcr rand.out $ak_ctx

  tpm2_pcrreset 16
  tpm2_evictcontrol -C o -c $handle_ek 2>/dev/null || true
  tpm2_evictcontrol -C o -c $handle_ak 2>/dev/null || true

  if [ $(ina "$@" "no-shut-down") -ne 0 ]; then
    shut_down
    echo "shutdown"
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

getrandom() {
  tpm2_getrandom -o rand.out $1
  local file_size=`ls -l rand.out | awk {'print $5'}`
  loaded_randomness=`cat rand.out | xxd -p -c $file_size`
}

# Key generation
tpm2_createek -c $handle_ek -G $ek_alg -u $output_ek_pub_pem -f pem

tpm2_createak -C $handle_ek -c $ak_ctx -G $ak_alg -g $digestAlg -s $signAlg \
-u $output_ak_pub_pem -f pem -n $output_ak_pub_name -p "$akpw"
tpm2_evictcontrol -Q -c $ak_ctx $handle_ak

# Quoting
getrandom 20
tpm2_quote -c $handle_ak -l sha256:15,16,22 -q $loaded_randomness \
-m $output_quote -s $output_quotesig -o $output_quotepcr -g $digestAlg -p "$akpw"

# Verify quote
tpm2_checkquote -u $output_ak_pub_pem -m $output_quote -s $output_quotesig \
-f $output_quotepcr -g $digestAlg -q $loaded_randomness

exit 0
