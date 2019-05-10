#!/bin/bash
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

tpm2_clear -Q

tpm2_createprimary -Q -a e -g sha256 -G rsa -o primary.ctx

tpm2_create -Q -g sha256 -G rsa -u certify.pub -r certify.priv  -C primary.ctx

tpm2_load -Q -C primary.ctx -u certify.pub -r certify.priv -n certify.name -o certify.ctx

tpm2_certify -Q -C primary.ctx -c certify.ctx -g sha256 -o attest.out -s sig.out

exit 0
