# SPDX-License-Identifier: BSD-3-Clause

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

trap - ERR

# Get PCR_Reset bad locality error
tpm2_pcrreset 0
if [ $? -eq 0 ]; then
  echo "Expected PCR reset of 0 to induce bad locality error"
  exit 1
fi

exit 0
