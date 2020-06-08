# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

    tpm2 flushcontext session.ctx 2>/dev/null || true

    rm -f session.ctx policy.pcr primary.ctx

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

tpm2 clear

tpm2 changeauth -c e endorsementpassword

tpm2 startauthsession -S session.ctx
tpm2 policypcr -l sha256:0 -L policy.pcr -S session.ctx
tpm2 flushcontext session.ctx

tpm2 setprimarypolicy -C e -L policy.pcr -g sha256 -P endorsementpassword

#
# Try changing the endorsement hierarchy password with the policy
#
tpm2 startauthsession -S session.ctx --policy-session
tpm2 policypcr -l sha256:0 -S session.ctx
tpm2 changeauth -c e -p session:session.ctx newendorsementpassword
tpm2 flushcontext session.ctx

#
# Use the new password to create a primary key
#
tpm2 createprimary -C e -c primary.ctx -P newendorsementpassword

exit 0
