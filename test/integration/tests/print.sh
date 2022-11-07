# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

ak_ctx=ak.ctx
ek_handle=0x81010017

ak_name_file=ak.name
ak_pubkey_file=ak.pub

quote_file=quote.bin
print_file=quote.yaml

pem_file=tsskeypriv
pem_pub=public_key
tss_prim=prim

cleanup() {
    rm -f $ak_name_file $ak_pubkey_file \
          $quote_file $print_file $ak_ctx \
          tpmt_public.ak ${tss_prim}\.*

    if [ "$1" != "no-shut-down" ]; then
       shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear

# Create signing key
tpm2 createek -Q -G rsa -c $ek_handle
tpm2 createak -Q -G rsa -g sha256 -s rsassa -C $ek_handle -c $ak_ctx\
  -u $ak_pubkey_file -n $ak_name_file

tpm2 readpublic -c $ak_ctx -f tpmt -o tpmt_public.ak

tpm2 print -t TPM2B_PUBLIC $ak_pubkey_file > $print_file
yaml_verify $print_file

tpm2 print -t TPMT_PUBLIC tpmt_public.ak > $print_file
yaml_verify $print_file

tpm2 print -t TPMT_PUBLIC -f pem tpmt_public.ak > $print_file
openssl rsa -noout -text -inform PEM -in $print_file -pubin

# Take PCR quote
tpm2 quote -Q -c $ak_ctx -l "sha256:0,2,4,9,10,11,12,17" -q "0f8beb45ac" \
-m $quote_file

# Print TPM's quote file
tpm2 print -t TPMS_ATTEST $quote_file > $print_file

# Check printed yaml
python << pyscript
from __future__ import print_function

import sys
import re
import yaml

with open("$print_file") as fd:
    yaml = yaml.safe_load(fd)

    assert(yaml["magic"] == "ff544347")
    assert(yaml["type"] == 8018)
    assert(yaml["extraData"] == "0f8beb45ac")

    quote = yaml["attested"]["quote"]

    # there should be only one pcr selection
    assert(quote["pcrSelect"]["count"] == 1)

    pcr_select = quote["pcrSelect"]["pcrSelections"][0]

    # pcr selection should match above options
    assert(pcr_select["hash"] == "11 (sha256)")
    assert(pcr_select["sizeofSelect"] == 3)
    assert(pcr_select["pcrSelect"] == "151e02")

    # pcrDigest should be lowercase hex encoded sha256sum per above options
    assert(re.match('^[0-9a-f]{64}$', quote["pcrDigest"]))

    print("OK")
pyscript

# negative testing
trap - ERR

tpm2 print $quote_file
if [ $? -eq 0 ]; then
  echo "Expected tpm2 print without -t to fail"
  exit 1
fi

# TSS Privkey
tpm2 createprimary -G rsa -C o \
-a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda" \
-c $tss_prim.ctx

tpm2 create -C $tss_prim.ctx -u $pem_file.pub -r $pem_file.priv

tpm2 encodeobject -C $tss_prim.ctx -u $pem_file.pub -r $pem_file.priv \
-o $pem_file.pem

tpm2 print -t TSSPRIVKEY_OBJ $pem_file.pem

tpm2 print -t TSSPRIVKEY_OBJ -f pem $pem_file.pem > $pem_pub.pem

openssl rsa -pubin -in $pem_pub.pem -text

tpm2 evictcontrol -c ${tss_prim}.ctx -o ${tss2_prim}.tr
tpm2 readpublic -n ${tss_prim}.name
name="$(tpm2 print -t ESYS_TR ${tss2_prim}.tr | grep 'name:' | cut -d' ' -f2-)"
expected_name="$(xxd -c256 -p ${tss_prim}.name)"
test "${name}" == "${expected_name}"

exit 0
