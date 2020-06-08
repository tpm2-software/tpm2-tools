# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    tpm2 clearcontrol

    tpm2 clear

    shut_down
}
trap cleanup EXIT

start_up

tpm2 clearcontrol -C l s
trap - ERR
tpm2 clear

trap onerror ERR
tpm2 clearcontrol
tpm2 clear

exit 0
