# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f policy.out test.policy

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

# Create a reference policy and compare
tpm2 startauthsession -S session.ctx

tpm2 policypassword -S session.ctx -L test.policy

tpm2 getpolicydigest -S session.ctx -o policy.out

tpm2 flushcontext session.ctx

#
# Test cpHash output
#
tpm2 clear
tpm2 flushcontext -t -l -s
tpm2 startauthsession -S session.ctx --policy-session

tpm2 getpolicydigest -S session.ctx --cphash cp.hash

TPM2_CC_PolicyGetDigest=00000189
SESSION_HANDLE=$(tpm2 sessionconfig session.ctx | grep Session-Handle | \
    awk -F ' 0x' '{print $2}')
echo $TPM2_CC_PolicyGetDigest$SESSION_HANDLE | xxd -r -p | \
    openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2
 if [ $? != 0 ]; then
    echo "cpHash doesn't match calculated value"
    exit 1
 fi

tpm2 flushcontext session.ctx

exit 0
