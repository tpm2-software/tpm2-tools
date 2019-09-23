# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

policyauthvalue=policy.dat
session_ctx=session.ctx
o_policy_digest=policy.digest
primary_key_ctx=prim.ctx
key_ctx=key.ctx
key_pub=key.pub
key_priv=key.priv
plain_txt=plain.txt
encrypted_txt=enc.txt
decrypted_txt=dec.txt
testpswd=testpswd

cleanup() {
    rm -f $policyauthvalue $session_ctx $o_policy_digest $primary_key_ctx \
    $key_ctx $key_pub $key_priv $plain_txt $encrypted_txt $decrypted_txt

    tpm2_flushcontext $session_ctx 2>/dev/null || true

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

echo "plaintext" > $plain_txt

tpm2_startauthsession -S $session_ctx
tpm2_policyauthvalue -S $session_ctx -L $policyauthvalue
tpm2_flushcontext $session_ctx
rm $session_ctx

tpm2_createprimary -C o -c $primary_key_ctx

tpm2_create -g sha256 -G aes -u $key_pub -r $key_priv -C $primary_key_ctx \
-L $policyauthvalue -p $testpswd

tpm2_load -C $primary_key_ctx -u $key_pub -r $key_priv -c $key_ctx
tpm2_encryptdecrypt -c $key_ctx -o $encrypted_txt -p $testpswd $plain_txt

tpm2_startauthsession --policy-session -S $session_ctx
tpm2_policyauthvalue -S $session_ctx -L $policyauthvalue
tpm2_encryptdecrypt -c $key_ctx -o $decrypted_txt -d \
-p session:$session_ctx+$testpswd $encrypted_txt
tpm2_flushcontext $session_ctx
rm $session_ctx

diff $plain_txt $decrypted_txt

exit 0
