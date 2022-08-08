# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

## Check cpHash output for TPM2_PCR_Reset
tpm2 pcrreset 23 --cphash cp.hash
TPM2_CC_PCR_Reset="0000013d"
pcrHandle="00000017"

echo -ne $TPM2_CC_PCR_Reset$pcrHandle | xxd -r -p | \
openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2

# Reset a resettable PCR
tpm2 pcrreset 23

# Reset more than one resettable PCR
tpm2 pcrreset 16 23

trap - ERR

# Get PCR_Reset bad locality error
tpm2 pcrreset 0
if [ $? -eq 0 ]; then
  echo "Expected PCR reset of 0 to induce bad locality error"
  exit 1
fi

exit 0
