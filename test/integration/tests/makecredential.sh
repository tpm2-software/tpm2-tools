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

handle_ek=0x81010007
handle_ak=0x81010008
ek_alg=rsa
ak_alg=rsa
digestAlg=sha256
signAlg=rsassa

file_input_data=secret.data
output_ek_pub=ek_pub.out
output_ak_pub=ak_pub.out
output_ak_pub_name=ak_name_pub.out
output_mkcredential=mkcredential.out

cleanup() {
    rm -f $output_ek_pub $output_ak_pub $output_ak_pub_name $output_mkcredential \
          $file_input_data output_ak grep.txt

    tpm2_evictcontrol -Q -ao -c $handle_ek 2>/dev/null || true
    tpm2_evictcontrol -Q -ao -c $handle_ak 2>/dev/null || true

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo "12345678" > $file_input_data

tpm2_createek -Q -c $handle_ek -G $ek_alg -p $output_ek_pub

tpm2_createak -Q -C $handle_ek  -k $handle_ak -G $ak_alg -D $digestAlg -s $signAlg -p $output_ak_pub -n $output_ak_pub_name

# Use -c in xxd so there is no line wrapping
file_size=`stat --printf="%s" $output_ak_pub_name`
Loadkeyname=`cat $output_ak_pub_name | xxd -p -c $file_size`

tpm2_makecredential -Q -e $output_ek_pub  -s $file_input_data  -n $Loadkeyname -o $output_mkcredential

tpm2_makecredential -Q -e $output_ek_pub  -s $file_input_data  -n $Loadkeyname -o $output_mkcredential --openssl-backend

exit 0
