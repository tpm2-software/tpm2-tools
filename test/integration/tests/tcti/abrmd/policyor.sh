#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2018, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

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
}
trap cleanup EXIT

start_up

cleanup

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
