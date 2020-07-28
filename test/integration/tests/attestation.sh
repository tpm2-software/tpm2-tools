# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

handle_ek=0x81010009
context_ak=ak.ctx
handle_nv=0x1500018
ek_alg=rsa
ak_alg=rsa
digestAlg=sha256
signAlg=rsassa
ownerpw=ownerpass
endorsepw=endorsepass
akpw=akpass
rand_pcr_value=6ea40aa7267bb71251c1de1c3605a3df759b86b22fa9f62aa298d4197cd88a38
debug_pcr=16
debug_pcr_list=15,16,22

file_input_data=secret.data
file_input_key=nv.data
output_ek_pub_pem=ekpub.pem
output_ek_pub=ek.pub
output_ak_pub_pem=akpub.pem
output_ak_pub=ak.pub
output_ak_pub_name=ak.name
output_mkcredential=mkcred.out
output_actcredential=actcred.out
output_quote=quote.out
output_quotesig=quotesig.out
output_quotepcr=quotepcr.out

cleanup() {
  rm -f $file_input_data $file_input_key $output_ek_pub $output_ek_pub_pem \
  $output_ak_pub $output_ak_pub_pem $output_ak_pub_name $output_mkcredential \
  $output_actcredential $output_quote $output_quotesig $output_quotepcr \
  $context_ak rand.out session.ctx

  tpm2 pcrreset -Q $debug_pcr
  tpm2 evictcontrol -Q -C o -c $handle_ek -P "$ownerpw" 2>/dev/null || true
  tpm2 evictcontrol -Q -C o -c $context_ak -P "$ownerpw" 2>/dev/null || true

  tpm2 nvundefine -Q $handle_nv -C o \
  -P "$ownerpw" 2>/dev/null || true

  if [ $(ina "$@" "no-shut-down") -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

start_up
cleanup "no-shut-down"

echo 12345678 > $file_input_data
echo 1234567890123456789012345678901 > $file_input_key

getrandom() {
  loaded_randomness=`tpm2 getrandom --hex $1`
}

tpm2 changeauth -c o "$ownerpw"
tpm2 changeauth -c e "$endorsepw"

# Key generation
tpm2 createek -Q -c $handle_ek -G $ek_alg -u $output_ek_pub_pem -f pem \
-w "$ownerpw" -P "$endorsepw"
tpm2 readpublic -Q -c $handle_ek -o $output_ek_pub

tpm2 createak -Q -C $handle_ek -c $context_ak -G $ak_alg -g $digestAlg \
-s $signAlg -u $output_ak_pub_pem -f pem -n $output_ak_pub_name -p "$akpw" \
-P "$endorsepw"
tpm2 readpublic -Q -c $context_ak -o $output_ak_pub


# Validate keys (registrar)
file_size=`ls -l $output_ak_pub_name | awk {'print $5'}`
loaded_key_name=`cat $output_ak_pub_name | xxd -p -c $file_size`
tpm2 makecredential -Q -T none -u $output_ek_pub -s $file_input_data \
-n $loaded_key_name -o $output_mkcredential

tpm2 startauthsession --policy-session -S session.ctx
tpm2 policysecret -S session.ctx -c e $endorsepw
tpm2 activatecredential -Q -c $context_ak -C $handle_ek \
-i $output_mkcredential -o $output_actcredential -p "$akpw" \
-P "session:session.ctx"
tpm2 flushcontext session.ctx
diff $file_input_data $output_actcredential


# Quoting
tpm2 pcrreset -Q $debug_pcr
tpm2 pcrextend -Q $debug_pcr:sha256=$rand_pcr_value
tpm2 pcrread -Q
getrandom 20
tpm2 quote -Q -c $context_ak -l $digestAlg:$debug_pcr_list \
-q $loaded_randomness -m $output_quote -s $output_quotesig -o $output_quotepcr \
-g $digestAlg -p "$akpw"


# Verify quote
tpm2 checkquote -Q -u $output_ak_pub_pem -m $output_quote -s $output_quotesig \
-f $output_quotepcr -g $digestAlg -q $loaded_randomness


# Save U key from verifier
tpm2 nvdefine -Q $handle_nv -C o -s 32 -a "ownerread|ownerwrite" \
-p "indexpass" -P "$ownerpw"
tpm2 nvwrite -Q $handle_nv -C o -P "$ownerpw" -i $file_input_key
tpm2 nvread -Q $handle_nv -C o -s 32 -P "$ownerpw"

exit 0
