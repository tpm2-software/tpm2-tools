#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;
#
# Copyright (c) 2019, Sebastien LE STUM
# All rights reserved.
#
#;**********************************************************************;

source helpers.sh

cleanup() {
    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

# Reset a resettable PCR
tpm2_pcrreset 23

# Reset more than one resettable PCR
tpm2_pcrreset 16 23

# Get PCR_Reset out of bound index error
tpm2_pcrreset 999 2>&1 1>/dev/null | grep -q "out of bound PCR"

# Get PCR_Reset wrong index error
tpm2_pcrreset toto 2>&1 1>/dev/null | grep -q "invalid PCR"

# Get PCR_Reset index out of range error
if ! tpm2_pcrreset 29 2>&1 1>/dev/null | grep -q "0x184"; then
    echo "tpm2_pcrreset on out of range PCR index didn't fail"
    exit 1
else
    true
fi

# Get PCR_Reset bad locality error
tpm2_pcrreset 0 2>&1 1>/dev/null | grep -q "0x907"

exit 0
