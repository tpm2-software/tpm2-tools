#!/bin/bash
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
    $session_ctx $policy_digest $concatenated

    tpm2_flushcontext -S $session_ctx 2>/dev/null || true

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

tpm2_startauthsession -S $session_ctx
tpm2_policyor -o $o_policy_digest -L sha256:$policy_1,$policy_2 -S $session_ctx
tpm2_flushcontext -S $session_ctx

diff $test_vector $o_policy_digest

exit 0
