# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

policy_1=policy.1
policy_2=policy.2
policy_init=policy.init
test_vector=test.vector
policyor_cc=policyor.cc
session_ctx=session.ctx
o_policy_digest=policy.digest
concatenated=con.cat

cleanup() {
    rm -f $policy_1 $policy_2 $policy_init $test_vector $policyor_cc \
    $session_ctx $policy_digest $concatenated \
    set1.pcr0.policy set2.pcr0.policy prim.ctx sealkey.priv sealkey.pub \
    sealkey.ctx policyOR

    tpm2 flushcontext $session_ctx 2>/dev/null || true

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

dd if=/dev/urandom of=$policy_1 bs=1 count=32
dd if=/dev/urandom of=$policy_2 bs=1 count=32
dd if=/dev/zero of=$policy_init bs=1 count=32
echo "00000171" | xxd -r -p > $policyor_cc
cat $policy_init $policyor_cc $policy_1 $policy_2 > $concatenated
openssl dgst -binary -sha256 $concatenated > $test_vector

tpm2 startauthsession -S $session_ctx
tpm2 policyor -L $o_policy_digest -S $session_ctx sha256:$policy_1,$policy_2
tpm2 flushcontext $session_ctx

diff $test_vector $o_policy_digest

# test that -l option and argument are concatenated
tpm2 startauthsession -S $session_ctx
tpm2 policyor -L $o_policy_digest -S $session_ctx -l sha256:$policy_1 sha256:$policy_2
tpm2 flushcontext $session_ctx

diff $test_vector $o_policy_digest

# Test case to compound two PCR policies

tpm2 pcrreset 23
tpm2 startauthsession -S session.ctx
tpm2 policypcr -S session.ctx -l sha1:23 -L set1.pcr0.policy
tpm2 flushcontext session.ctx
rm session.ctx

tpm2 pcrextend 23:sha1=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15
tpm2 startauthsession -S session.ctx
tpm2 policypcr -S session.ctx -l sha1:23 -L set2.pcr0.policy
tpm2 flushcontext session.ctx
rm session.ctx

tpm2 startauthsession -S session.ctx
tpm2 policyor -S session.ctx -L policyOR \
sha256:set1.pcr0.policy,set2.pcr0.policy
tpm2 flushcontext session.ctx
rm session.ctx

tpm2 createprimary -C o -c prim.ctx
tpm2 create -g sha256 -u sealkey.pub -r sealkey.priv -L policyOR -C prim.ctx \
-i- <<< "secretpass"
tpm2 load -C prim.ctx -c sealkey.ctx -u sealkey.pub -r sealkey.priv

tpm2 startauthsession -S session.ctx --policy-session
tpm2 policypcr -S session.ctx -l sha1:23
tpm2 policyor -S session.ctx -L policyOR \
sha256:set1.pcr0.policy,set2.pcr0.policy
unsealed=`tpm2 unseal -p session:session.ctx -c sealkey.ctx`
echo $unsealed
tpm2 flushcontext session.ctx
rm session.ctx

tpm2 pcrextend 23:sha1=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15
tpm2 startauthsession -S session.ctx --policy-session
tpm2 policypcr -S session.ctx -l sha1:23

tpm2 pcrreset 23

tpm2 startauthsession -S session.ctx --policy-session
tpm2 policypcr -S session.ctx -l sha1:23
tpm2 policyor -S session.ctx -L policyOR \
sha256:set1.pcr0.policy,set2.pcr0.policy
unsealed=`tpm2 unseal -p session:session.ctx -c sealkey.ctx`
echo $unsealed
tpm2 flushcontext session.ctx
rm session.ctx

exit 0
