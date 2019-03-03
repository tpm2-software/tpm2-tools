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

TPM_RH_OWNER=0x40000001
SEALED_SECRET="SEALED-SECRET"
session_ctx=session.ctx
o_policy_digest=policy.digest
primary_ctx=prim.ctx
seal_key_pub=sealing_key.pub
seal_key_priv=sealing_key.priv
seal_key_ctx=sealing_key.ctx


cleanup() {
  rm -f  $session_ctx $o_policy_digest $primary_ctx $seal_key_pub $seal_key_priv\
   $seal_key_ctx

  tpm2_flushcontext -S $session_ctx 2>/dev/null || true

  tpm2_clear
}
trap cleanup EXIT

start_up

cleanup

tpm2_clear

tpm2_changeauth -o ownerauth

#Create Policy
tpm2_startauthsession -S $session_ctx
tpm2_policysecret -S $session_ctx -c $TPM_RH_OWNER -o $o_policy_digest ownerauth
tpm2_flushcontext -S $session_ctx
rm $session_ctx

#Create and Load Object
tpm2_createprimary -Q -a o  -o $primary_ctx -P ownerauth
tpm2_create -Q -g sha256 -u $seal_key_pub -r $seal_key_priv -C $primary_ctx\
  -L $o_policy_digest -I- <<< $SEALED_SECRET
tpm2_load -C $primary_ctx -u $seal_key_pub -r $seal_key_priv -o $seal_key_ctx

#Satisfy policy and unseal data
tpm2_startauthsession -a -S $session_ctx
echo -n "ownerauth" | tpm2_policysecret -S $session_ctx -c $TPM_RH_OWNER -o $o_policy_digest -
unsealed=`tpm2_unseal -p"session:$session_ctx" -c $seal_key_ctx`
tpm2_flushcontext -S $session_ctx
rm $session_ctx

test "$unsealed" == "$SEALED_SECRET"

if [ $? != 0 ]; then
  echo "failed policysecret integration test"
  exit 1
fi

exit 0
