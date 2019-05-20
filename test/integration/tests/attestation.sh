#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

handle_ek=0x81010009
context_ak=ak.ctx
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
  rm -f $file_input_data $file_input_key $output_ek_pub $output_ek_pub_pem $output_ak_pub \
        $output_ak_pub_pem $output_ak_pub_name $output_mkcredential \
        $output_actcredential $output_quote $output_quotesig $output_quotepcr $context_ak rand.out

  tpm2_pcrreset -Q $debug_pcr
  tpm2_evictcontrol -Q -a o -c $handle_ek -P "$ownerpw" 2>/dev/null || true
  tpm2_evictcontrol -Q -a o -c $context_ak -P "$ownerpw" 2>/dev/null || true

  tpm2_nvrelease -Q -x $handle_nv -a $handle_hier -P "$ownerpw" 2>/dev/null || true

  tpm2_changeauth -Q -W "$ownerpw" -E "$endorsepw" 2>/dev/null || true

  ina "$@" "no-shut-down"
  if [ $? -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

start_up
cleanup "no-shut-down"

echo "12345678" > $file_input_data
echo "1234567890123456789012345678901" > $file_input_key

getrandom() {
  tpm2_getrandom -Q -o rand.out $1
  local file_size=`stat --printf="%s" rand.out`
  loaded_randomness=`cat rand.out | xxd -p -c $file_size`
}


tpm2_changeauth -Q -w "$ownerpw" -e "$endorsepw"

# Key generation
tpm2_createek -Q -c $handle_ek -G $ek_alg -p $output_ek_pub_pem -f pem -P "$ekpw" -w "$ownerpw" -e "$endorsepw"
tpm2_readpublic -Q -c $handle_ek -o $output_ek_pub

tpm2_createak -Q -C $handle_ek -c $context_ak -G $ak_alg -D $digestAlg -s $signAlg -p $output_ak_pub_pem -f pem -n $output_ak_pub_name -P "$akpw" -e "$endorsepw"
tpm2_readpublic -Q -c $context_ak -o $output_ak_pub


# Validate keys (registrar)
file_size=`stat --printf="%s" $output_ak_pub_name`
loaded_key_name=`cat $output_ak_pub_name | xxd -p -c $file_size`
tpm2_makecredential -Q -T none -e $output_ek_pub -s $file_input_data -n $loaded_key_name -o $output_mkcredential
tpm2_activatecredential -Q -c $context_ak -C $handle_ek -i $output_mkcredential -o $output_actcredential -P "$akpw" -E "$endorsepw"
diff $file_input_data $output_actcredential


# Quoting
tpm2_pcrreset -Q $debug_pcr
tpm2_pcrextend -Q $debug_pcr:sha256=$rand_pcr_value
tpm2_pcrlist -Q
getrandom 20
tpm2_quote -Q -C $context_ak -L $digestAlg:$debug_pcr_list -q $loaded_randomness -m $output_quote -s $output_quotesig -p $output_quotepcr -g $digestAlg -P "$akpw"


# Verify quote
tpm2_checkquote -Q -u $output_ak_pub_pem -m $output_quote -s $output_quotesig -F $output_quotepcr -g $digestAlg -q $loaded_randomness


# Save U key from verifier
tpm2_nvdefine -Q -x $handle_nv -a $handle_hier -s 32 -b "ownerread|ownerwrite" -p "indexpass" -P "$ownerpw"
tpm2_nvwrite -Q -x $handle_nv -a $handle_hier -P "$ownerpw" $file_input_key
tpm2_nvread -Q -x $handle_nv -a $handle_hier -s 32 -P "$ownerpw"

exit 0
