# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

    tpm2 flushcontext session.ctx 2>/dev/null || true

    tpm2 startauthsession --policy-session -S session.ctx
    tpm2 policyauthvalue -S session.ctx
    tpm2 policycommandcode -S session.ctx TPM2_CC_NV_UndefineSpaceSpecial
    tpm2 nvundefine -S session.ctx 1 2>/dev/null || true

    tpm2 flushcontext session.ctx 2>/dev/null || true

    rm -f policy.dat session.ctx

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

tpm2 startauthsession -S session.ctx

tpm2 policyauthvalue -S session.ctx

tpm2 policycommandcode -S session.ctx TPM2_CC_NV_UndefineSpaceSpecial -L policy.dat

tpm2 nvdefine -C p -s 32 -a "ppread|ppwrite|authread|authwrite|platformcreate|policydelete|write_stclear|read_stclear" -L policy.dat 1

tpm2 flushcontext session.ctx

tpm2 startauthsession --policy-session -S session.ctx

tpm2 policyauthvalue -S session.ctx

tpm2 policycommandcode -S session.ctx TPM2_CC_NV_UndefineSpaceSpecial

tpm2 nvundefine -S session.ctx 1

exit 0
