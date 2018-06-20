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
    rm -f ek.pub ak.pub ak.name ak.name ak.log

    # Evict persistent handles, we want them to always succeed and never trip
    # the onerror trap.
    tpm2_evictcontrol -Q -a o -c 0x8101000b 2>/dev/null || true
    tpm2_evictcontrol -Q -a o -c 0x8101000c 2>/dev/null || true

    # clear tpm state
    tpm2_clear

    if [ "$1" != "no-shut-down" ]; then
      shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_createek -Q -c 0x8101000b -G rsa -p ek.pub

tpm2_createak -Q -C 0x8101000b -k 0x8101000c -G rsa -D sha256 -s rsassa -p ak.pub -n ak.name

# Find a vacant persistent handle
tpm2_createak -C 0x8101000b -k - -G rsa -D sha256 -s rsassa -p ak.pub -n ak.name > ak.log
phandle=`yaml_get_kv ak.log \"ak\-persistent\-handle\"`
tpm2_evictcontrol -Q -a o -c $phandle

exit 0
