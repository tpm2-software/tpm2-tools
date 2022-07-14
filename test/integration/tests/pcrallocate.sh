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

## Check cpHash output for TPM2_PCR_Allocate
tpm2 pcrallocate sha1:0,1,2 --cphash cp.hash
TPM2_CC_PCR_Allocate="0000012b"
handle_Name="4000000c"
Param_pcrAllocation="00 00 00 01 00 04 03 07 00 00"

echo -ne $TPM2_CC_PCR_Allocate$handle_Name$Param_pcrAllocation | xxd -r -p | \
openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2

# Store the old banks because e.g. some TPM-simuators don't support SHA512
OLDBANKS=$(tpm2 getcap pcrs | grep bank | sed 's/.*bank\: \(.*\)/+\1:all/' | \
tr -d "\n")

echo "OLDBANKS: $OLDBANKS"

tpm2 pcrallocate -P "" sha1:7,8,9,10,16,17,18,19+sha256:all \
    | tee out.yml
yaml_verify out.yml

tpm2 pcrallocate sha1:all+sha256:all | tee out.yml
yaml_verify out.yml

tpm2 pcrallocate ${OLDBANKS:1}

#Note: We cannot check if the allocations were performed by the TPM, since they
#      will only take effect once the TPM reboots.

exit 0
