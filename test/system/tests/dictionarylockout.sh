#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2016, Intel Corporation
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
###this script use for test the implementation tpm2_dictionarylockout 

source helpers.sh

out=out.yaml

cleanup() {
    rm -f $out
}
trap cleanup EXIT

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

tpm2_dictionarylockout -Q -V -c &>/dev/null

tpm2_dictionarylockout -s -n 5 -t 6 -l 7

tpm2_getcap -c properties-variable > $out
v=$(yaml_get_kv "$out" \"TPM2_PT_MAX_AUTH_FAIL\")
if [ $v -ne 5 ];then
  echo "Failure: setting up the number of allowed tries in the lockout parameters"
  exit 1
fi

v=$(yaml_get_kv "$out" \"TPM2_PT_LOCKOUT_INTERVAL\")
if [ $v -ne 6 ];then
  echo "Failure: setting up the lockout period in the lockout parameters"
  exit 1
fi

v=$(yaml_get_kv "$out" \"TPM2_PT_LOCKOUT_RECOVERY\")
if [ $v -ne 7 ];then
  echo "Failure: setting up the lockout recovery period in the lockout parameters"
  exit 1
fi

exit 0
