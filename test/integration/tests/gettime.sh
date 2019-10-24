# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
	rm -f attest.sig attest.data
}
trap cleanup EXIT

start_up

tpm2_createprimary -C e -c primary.ctx

tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx

tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx

tpm2_gettime -c rsa.ctx -o attest.sig --attestation attest.data

exit 0
