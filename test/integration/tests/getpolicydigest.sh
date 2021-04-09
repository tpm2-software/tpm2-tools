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

exit 0
