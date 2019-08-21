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

# Store the old banks because e.g. some TPM-simuators don't support SHA512
OLDBANKS=$(tpm2_getcap pcrs | grep bank | sed 's/.*bank\: \(.*\)/+\1:all/' | \
tr -d "\n")

echo "OLDBANKS: $OLDBANKS"

tpm2_pcrallocate -P "" sha1:7,8,9,10,16,17,18,19+sha256:all \
    | tee out.yml
yaml_verify out.yml

tpm2_pcrallocate sha1:all+sha256:all | tee out.yml
yaml_verify out.yml

tpm2_pcrallocate ${OLDBANKS:1}

#Note: We cannot check if the allocations were performed by the TPM, since they
#      will only take effect once the TPM reboots.

exit 0
