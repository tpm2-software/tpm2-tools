# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

    rm -f \
    prim.ctx signing_key.ctx signing_key.pub signing_key.priv \
    att.data att.sig cp.hash rp.hash cphash.bin rphash.bin zero.bin

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

tpm2 clear

#
# Get audit digest for a TPM command TPM2_GetRandom using and audit session
#

tpm2 createprimary -Q -C e -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 startauthsession -S session.ctx --audit-session

tpm2 getrandom 8 -S session.ctx --cphash cp.hash --rphash rp.hash

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

exit 0
