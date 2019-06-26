# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm secret.txt key.ctx key.pub key.priv primary.ctx

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

tpm2_clear

tpm2_changeauth -c o $ownerPasswd
tpm2_changeauth -c e $endorsePasswd
tpm2_changeauth -c l $lockPasswd

tpm2_changeauth -c o -p $ownerPasswd $new_ownerPasswd
tpm2_changeauth -c e -p $endorsePasswd $new_endorsePasswd
tpm2_changeauth -c l -p $lockPasswd $new_lockPasswd

tpm2_clear -L $new_lockPasswd

tpm2_changeauth -c o $ownerPasswd
tpm2_changeauth -c e $endorsePasswd
tpm2_changeauth -c l $lockPasswd

echo -n $lockPasswd > secret.txt
tpm2_clear -L "file:secret.txt"

# Test changing an objects auth
tpm2_createprimary -Q -a o -o primary.ctx
tpm2_create -Q -C primary.ctx -p foo -u key.pub -r key.priv
tpm2_load -Q -C primary.ctx -u key.pub -r key.priv -o key.ctx
tpm2_changeauth -C primary.ctx -p foo -c key.ctx -r new.priv bar

exit 0
