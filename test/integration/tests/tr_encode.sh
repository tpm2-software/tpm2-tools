# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f *.tr *.ctx *.pub

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 createprimary -c primary.ctx
tpm2 evictcontrol -c primary.ctx -o primary.tr 0x81000002
tpm2 readpublic -c primary.tr -o primary.pub
tpm2 tr_encode -c 0x81000002 -u primary.pub -o primary2.tr
cmp primary.tr primary2.tr
