#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    tpm2_clearcontrol

    tpm2_clear

    shut_down
}
trap cleanup EXIT

start_up

tpm2_clearcontrol -a l s
trap - ERR
tpm2_clear

trap onerror ERR
tpm2_clearcontrol
tpm2_clear

exit 0
