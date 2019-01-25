#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
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

cleanup() {
    rm secret.txt key.ctx key.pub key.priv primary.ctx
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

tpm2_changeauth -o $ownerPasswd -e $endorsePasswd -l $lockPasswd

tpm2_changeauth -O $ownerPasswd -E $endorsePasswd -L $lockPasswd -o $new_ownerPasswd -e $new_endorsePasswd -l $new_lockPasswd

tpm2_clear -L $new_lockPasswd

tpm2_changeauth -o $ownerPasswd -e $endorsePasswd -l $lockPasswd

echo -n $lockPasswd > secret.txt
tpm2_clear -L "file:secret.txt"

# Test changing an objects auth
tpm2_createprimary -Q -a o -o primary.ctx
tpm2_create -Q -C primary.ctx -p foo -u key.pub -r key.priv
tpm2_load -Q -C primary.ctx -u key.pub -r key.priv -o key.ctx
tpm2_changeauth -a primary.ctx -P foo -p bar -c key.ctx -r new.priv


exit 0
