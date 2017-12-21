#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2017, Alibaba Group
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

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

cleanup() {
    rm -f saved_session.ctx
}
trap cleanup EXIT

cleanup
tpm2_clear

# Test for flushing the specified handle
tpm2_createprimary -Q -H o -g sha256 -G rsa
# tpm2-abrmd may save the transient object and restore it when using
res=`tpm2_getcap -c handles-transient` 
if [ -n "$res" ]; then
    tpm2_flushcontext -Q -H 0x80000000
fi

# Test for flushing a transient object
tpm2_createprimary -Q -H o -g sha256 -G rsa
tpm2_flushcontext -Q -t

# Test for flushing a loaded session
tpm2_createpolicy -Q -a -P -L sha256:0
tpm2_flushcontext -Q -l

# Test for flushing a saved session
tpm2_createpolicy -Q -a -P -L sha256:0 -S saved_session.ctx
tpm2_flushcontext -Q -s

cleanup

exit 0
