# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm key.ctx key.pub key.priv primary.ctx

    shut_down
}
trap cleanup EXIT

start_up

ownerPasswd=abc123
endorsePasswd=abc123
lockPasswd=abc123
new_ownerPasswd=newpswd
new_endorsePasswd=newpswd
new_lockPasswd=newpswd

tpm2 clear

tpm2 changeauth -c o $ownerPasswd
tpm2 changeauth -c e $endorsePasswd
tpm2 changeauth -c l $lockPasswd

tpm2 changeauth -c o -p $ownerPasswd $new_ownerPasswd
tpm2 changeauth -c e -p $endorsePasswd $new_endorsePasswd
tpm2 changeauth -c l -p $lockPasswd $new_lockPasswd

tpm2 clear $new_lockPasswd

tpm2 changeauth -c o $ownerPasswd
tpm2 changeauth -c e $endorsePasswd
tpm2 changeauth -c l $lockPasswd

tpm2 clear $lockPasswd

# Test changing an objects auth
tpm2 createprimary -Q -C o -c primary.ctx
tpm2 create -Q -C primary.ctx -p foo -u key.pub -r key.priv
tpm2 load -Q -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2 changeauth -C primary.ctx -p foo -c key.ctx -r new.priv bar

# Test changing an NV index auth
tpm2 startauthsession -S session.ctx
tpm2 policycommandcode -S session.ctx -L policy.nvchange TPM2_CC_NV_ChangeAuth
tpm2 flushcontext session.ctx
NVIndex=0x1500015
tpm2 nvdefine   $NVIndex -C o -s 32 -a "authread|authwrite" -L policy.nvchange
tpm2 startauthsession --policy-session -S session.ctx
tpm2 policycommandcode -S session.ctx -L policy.nvchange TPM2_CC_NV_ChangeAuth
tpm2 changeauth -p session:session.ctx -c $NVIndex newindexauth

exit 0
