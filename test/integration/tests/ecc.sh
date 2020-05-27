# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f pass1_ecc.q pass2_ecc.q ecc.ctr

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

# TPM2_EC_Ephemeral
## Check if commit counter is zero on first invocation
tpm2_ecephermal -u pass1_ecc.q -t pass1_ecc.ctr ecc256
xxd -p pass1_ecc.ctr | grep 0000
## Check if commit counter increments to 1 on second invocation
tpm2_ecephermal -u pass2_ecc.q -t pass2_ecc.ctr ecc256
xxd -p pass2_ecc.ctr | grep 0001

exit 0
