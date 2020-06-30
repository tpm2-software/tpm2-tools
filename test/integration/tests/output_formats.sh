# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

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
handle_ak_file=ak.handle
ak_ctx=ak.ctx

file_hash_input="hash.in"
file_hash_ticket=hash.ticket
file_hash_result=hash.result
file_sig_base=hash.sig
alg_hash=sha256

file_quote_msg=quote.msg
file_quote_sig_base=quote.sig

cleanup() {
    rm -f "$file_pubek_base".*
    rm -f "$file_pubak_tss" "$file_pubak_name" "$file_pubak_pem"
    rm -f "$file_hash_ticket" "$file_hash_result" "$file_sig_base".*
    rm -f "$file_quote_msg" "$file_quote_sig_base".* $file_hash_input
    rm -f primary.ctx ecc.ctx ecc.pub ecc.priv ecc.fmt.pub $ak_ctx

    # Evict persistent handles, we want them to always succeed and never trip
    # the onerror trap.
    for handle in $handle_ek $handle_ak; do
        tpm2 evictcontrol -Q -C o -c $handle 2>/dev/null || true
    done

    shut_down
}
trap cleanup EXIT

start_up

head -c 4096 /dev/urandom > $file_hash_input

tpm2 createek -Q -G $alg_ek -u "$file_pubek_orig" -c $handle_ek

for fmt in tss pem der; do

    this_key="${file_pubek_base}.${fmt}"

    tpm2 readpublic -Q -c $handle_ek -f "$fmt" -o "$this_key"

    if [ "$fmt" = tss ]; then
        diff "$file_pubek_orig" "$this_key" > /dev/null
    else
        openssl rsa -pubin -inform "$fmt" -text -in "$this_key" &> /dev/null
    fi

done

tpm2 createak -Q -G $alg_ak -C $handle_ek -c $ak_ctx -u "$file_pubak_tss" \
-n "$file_pubak_name"
echo "tpm2 evictcontrol -Q -c $ak_ctx -o $handle_ak_file" $handle_ak
tpm2 evictcontrol -Q -c $ak_ctx -o $handle_ak_file $handle_ak

tpm2 readpublic -Q -c $handle_ak_file -f "pem" -o "$file_pubak_pem"

tpm2 hash -Q -C e -g $alg_hash -t "$file_hash_ticket" -o "$file_hash_result" \
"$file_hash_input"

for fmt in tss plain; do
    this_sig="${file_sig_base}.${fmt}"
    tpm2 sign -Q -c $handle_ak -g $alg_hash -f $fmt -o "${this_sig}" \
    -t "${file_hash_ticket}" "${file_hash_input}"

    if [ "$fmt" = plain ]; then
        openssl dgst -verify "$file_pubak_pem" -keyform pem -${alg_hash} \
        -signature "$this_sig" "$file_hash_input" > /dev/null
    fi
done

for fmt in tss plain; do
    this_sig="${file_quote_sig_base}.${fmt}"
    tpm2 quote -Q -c $handle_ak -l "$alg_hash":0 -f $fmt -m "$file_quote_msg" \
    -s "$this_sig"

    if [ "$fmt" = plain ]; then
        openssl dgst -verify "$file_pubak_pem" -keyform pem -${alg_hash} \
        -signature "$this_sig" "$file_quote_msg" > /dev/null
    fi
done

#
# Test ECC keys
#
tpm2 createprimary -c primary.ctx
tpm2 create -Q -C primary.ctx -G ecc -u ecc.pub -r ecc.priv
tpm2 load -C primary.ctx -u ecc.pub -r ecc.priv -c ecc.ctx

for fmt in pem der; do

    tpm2 readpublic -Q -c ecc.ctx -f "$fmt" -o ecc.fmt.pub

    openssl ec -pubin -inform "$fmt" -text -in ecc.fmt.pub &> /dev/null
done

exit 0
