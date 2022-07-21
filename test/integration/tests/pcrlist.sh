# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f pcrs.out

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

## Check cpHash output for TPM2_PCR_Read
tpm2 pcrread sha1:0,1,2 --cphash cp.hash
TPM2_CC_PCR_Read="0000017e"
Param_pcrSelectionIn="00 00 00 01 00 04 03 07 00 00"

echo -ne $TPM2_CC_PCR_Read$Param_pcrSelectionIn | xxd -r -p | \
openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2

tpm2 pcrread > pcrs.out
yaml_verify pcrs.out

tpm2 pcrread -Q 0x04

tpm2 pcrread -Q -o pcrs.out 0x04:17,18,19+sha256:0,17,18,19

test -e pcrs.out

tpm2 pcrread -Q

exit 0
