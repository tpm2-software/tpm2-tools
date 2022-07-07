# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

start_up

cleanup() {
    rm -f saved_session.ctx

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

cleanup "no-shut-down"
tpm2 clear

## Check cpHash output
tpm2 startauthsession -S session.ctx
Param_flushHandle="$(tpm2 sessionconfig session.ctx  | \
grep 'Session-Handle' | cut -d' ' -f2-2)"
tpm2 flushcontext $Param_flushHandle --cphash cp.hash
TPM2_CC_flushContext="00000165"

echo -ne $TPM2_CC_flushContext$Param_flushHandle | xxd -r -p | \
openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2

# Test for flushing the specified handle
tpm2 createprimary -Q -C o -g sha256 -G rsa
# tpm2-abrmd may save the transient object and restore it when using
res=`tpm2 getcap handles-transient`
if [ -n "$res" ]; then
    tpm2 flushcontext -Q -c 0x80000000
fi

# Test for flushing a transient object
tpm2 createprimary -Q -C o -g sha256 -G rsa
# make sure multiple options don't overflow
# bug: https://github.com/tpm2-software/tpm2-tools/issues/3035
tpm2 flushcontext -Q -ttttttttttt

# Test for flushing a loaded session
tpm2 createpolicy -Q --policy-session --policy-pcr -l sha256:0
tpm2 flushcontext -Q -l

cleanup "no-shut-down"

exit 0
