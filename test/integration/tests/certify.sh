# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f primary.ctx certify.ctx certify.pub certify.priv certify.name \
    attest.out sig.out &>/dev/null

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c primary.ctx

tpm2 create -Q -g sha256 -G rsa -u certify.pub -r certify.priv -C primary.ctx

tpm2 load -Q -C primary.ctx -u certify.pub -r certify.priv -n certify.name \
-c certify.ctx

tpm2 certify -Q -c primary.ctx -C certify.ctx -g sha256 -o attest.out -s sig.out

exit 0
