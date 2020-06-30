# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f pcrs.out

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 pcrread > pcrs.out
yaml_verify pcrs.out

tpm2 pcrread -Q 0x04

tpm2 pcrread -Q -o pcrs.out 0x04:17,18,19+sha256:0,17,18,19

test -e pcrs.out

tpm2 pcrread -Q

exit 0
