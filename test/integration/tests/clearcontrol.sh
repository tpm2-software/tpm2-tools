#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    tpm2_clearcontrol -c -a p

    tpm2_clear

    shut_down
}
trap cleanup EXIT

start_up

cleanup

tpm2_clearcontrol -s
trap - ERR
tpm2_clear

trap onerror ERR
tpm2_clearcontrol -c -a p
tpm2_clear

exit 0
