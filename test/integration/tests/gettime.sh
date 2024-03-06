# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f attest.sig attest.data
    if [ "$1" != "no-shut-down" ]; then
	shut_down
    fi
}
trap cleanup EXIT

start_up

tpm2 createprimary -C e -c primary.ctx

tpm2 create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx

tpm2 load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx

tpm2 gettime -c rsa.ctx -o attest.sig --attestation attest.data

tpm2 print -t TPMS_ATTEST attest.data

exit 0
