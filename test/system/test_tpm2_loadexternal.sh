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
alg_primary_obj=0x000B
alg_primary_key=0x0001
alg_create_obj=0x000B
alg_create_key=0x0008

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_loadexternal_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_loadexternal_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_loadexternal_key_name=name.loadexternal_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_loadexternal_key_ctx=ctx_loadexternal_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_loadexternal_output=loadexternal_"$file_loadexternal_key_ctx"

Handle_parent=0x81010019

cleanup() {
  rm -f $file_primary_key_ctx $file_loadexternal_key_pub $file_loadexternal_key_priv \
         $file_loadexternal_key_name $file_loadexternal_key_ctx \
         $file_loadexternal_output

  if [ "$1" != "keep_handle" ]; then
    tpm2_evictcontrol -Q -Ao -H $Handle_parent 2>/dev/null || true
  fi
}
trap cleanup EXIT

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

cleanup

tpm2_takeownership -c

tpm2_createprimary -Q -H e -g $alg_primary_obj -G $alg_primary_key -C $file_primary_key_ctx

tpm2_create -Q -g $alg_create_obj -G $alg_create_key -u $file_loadexternal_key_pub -r $file_loadexternal_key_priv  -c $file_primary_key_ctx

tpm2_loadexternal -Q -H n   -u $file_loadexternal_key_pub   -C $file_loadexternal_key_ctx

tpm2_evictcontrol -Q -A o -c $file_primary_key_ctx  -S $Handle_parent

# Test with Handle
cleanup keep_handle

tpm2_create -Q -H $Handle_parent   -g $alg_create_obj  -G $alg_create_key -u $file_loadexternal_key_pub  -r  $file_loadexternal_key_priv

tpm2_loadexternal -Q -H n   -u $file_loadexternal_key_pub

exit 0
