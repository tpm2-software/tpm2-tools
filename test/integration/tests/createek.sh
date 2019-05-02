#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
# All rights reserved.
#
#;**********************************************************************;

source helpers.sh

cleanup() {
    rm -f ek.pub ek.log ek.template ek.nonce

    # Evict persistent handles, we want them to always succeed and never trip
    # the onerror trap.
    tpm2_evictcontrol -Q -a o -c 0x81010005 2>/dev/null || true

    if [ "$1" != "no-shut-down" ]; then
      shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_createek -c 0x81010005 -G rsa -p ek.pub

cleanup "no-shut-down"

tpm2_createek -c - -G rsa -p ek.pub > ek.log
phandle=`yaml_get_kv ek.log \"persistent\-handle\"`
tpm2_evictcontrol -Q -a o -c $phandle

cleanup "no-shut-down"

tpm2_createek -G rsa -p ek.pub

cleanup "no-shut-down"

ek_nonce_index=0x01c00003
ek_template_index=0x01c00004

# Define RSA EK template
nbytes=$(wc -c $TPM2_TOOLS_TEST_FIXTURES/ek-template-default.bin | cut -f1 -d' ')
tpm2_nvdefine -Q -x $ek_template_index -a o -s $nbytes -b "ownerread|policywrite|ownerwrite"
tpm2_nvwrite -Q -x $ek_template_index -a o $TPM2_TOOLS_TEST_FIXTURES/ek-template-default.bin

# Define RSA EK nonce
echo -n -e '\0' > ek.nonce
tpm2_nvdefine -Q -x $ek_nonce_index -a o -s 1 -b "ownerread|policywrite|ownerwrite"
tpm2_nvwrite -Q -x $ek_nonce_index -a o ek.nonce

tpm2_createek -t -G rsa -p ek.pub

cleanup "no-shut-down"

exit 0
