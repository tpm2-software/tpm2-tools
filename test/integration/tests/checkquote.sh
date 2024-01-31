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
  $output_quote $output_quotesig $output_quotepcr rand.out $ak_ctx \
  pcr.bin

  tpm2 pcrreset 16
  tpm2 evictcontrol -C o -c $handle_ek 2>/dev/null || true
  tpm2 evictcontrol -C o -c $handle_ak 2>/dev/null || true

  if [ $(ina "$@" "no-shut-down") -ne 0 ]; then
    shut_down
    echo "shutdown"
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

getrandom() {
  tpm2 getrandom -o rand.out $1
  local file_size=`ls -l rand.out | awk {'print $5'}`
  loaded_randomness=`cat rand.out | xxd -p -c $file_size`
}

# Key generation
tpm2 createek -c $handle_ek -G $ek_alg -u $output_ek_pub_pem -f pem

tpm2 createak -C $handle_ek -c $ak_ctx -G $ak_alg -g $digestAlg -s $signAlg \
-u $output_ak_pub_pem -f pem -n $output_ak_pub_name -p "$akpw"
tpm2 evictcontrol -Q -c $ak_ctx $handle_ak

# Quoting
getrandom 20
tpm2 quote -c $handle_ak -l sha256:15,16,22 -q $loaded_randomness \
-m $output_quote -s $output_quotesig -o $output_quotepcr -g $digestAlg -p "$akpw"

# Verify quote
tpm2 checkquote -u $output_ak_pub_pem -m $output_quote -s $output_quotesig \
-f $output_quotepcr -g $digestAlg -q $loaded_randomness

# Verify EC

tpm2 createek -G ecc -c ecc.ek

tpm2 createak -C ecc.ek -c ecc.ak -G ecc -g sha256 -s ecdsa

tpm2 readpublic -c ecc.ak -f pem -o ecc.ak.pem

tpm2 getrandom -o nonce.bin 20

tpm2 quote -c ecc.ak -l sha256:15,16,22 -q nonce.bin -m quote.bin -s quote.sig -o quote.pcr -g sha256

tpm2 checkquote -u ecc.ak.pem -m quote.bin -s quote.sig -f quote.pcr -g sha256 -q nonce.bin

# Verify that tss format works
tpm2 readpublic -c ecc.ak -f tss -o ecc.ak.tss

tpm2 checkquote -u ecc.ak.tss -m quote.bin -s quote.sig -f quote.pcr -g sha256 -q nonce.bin

# Verify the tpmt format works
tpm2 readpublic -c ecc.ak -f tpmt -o ecc.ak.tpmt

tpm2 checkquote -u ecc.ak.tpmt -m quote.bin -s quote.sig -f quote.pcr -g sha256 -q nonce.bin

# Verify that the plain tpm2_pcrread output can be passed to the checkquote tool
tpm2 pcrread sha256:15,16,22 -o pcr.bin

tpm2 checkquote -u ecc.ak.tpmt -m quote.bin -s quote.sig -g sha256 -q nonce.bin \
     -f pcr.bin -l sha256:15,16,22

# Verify quote with

tpm2 createprimary -Q -C e -G rsa2048:rsapss-sha256:null -c ek.ctx -o ek.pub -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|restricted'

# Provide scheme explicitly
tpm2 quote -Q -c ek.ctx -g sha256 -l sha1:0,1,2,3 -o quote.pcrs -m quote.msg -s quote.sig --scheme=rsapss 

# Signature verification
tpm2 checkquote -u ek.pub -m quote.msg -s quote.sig -f quote.pcrs

exit 0
