#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2017-2018, Intel Corporation
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

#this script is for hash case testing

source helpers.sh

hash_out_file=hash.out
hash_in_file=hash.in
yaml_out_file=pcr_list.yaml

cleanup() {
  rm -f $hash_in_file $hash_out_file $yaml_out_file

  shut_down
}
trap cleanup EXIT

start_up

echo "T0naX0u123abc" > $hash_in_file

# Run FILE and stdin as FILE
tpm2_pcrevent -Q $hash_in_file
tpm2_pcrevent -Q < $hash_in_file

# Test that fifo stdin works
cat $hash_in_file | tpm2_pcrevent > $hash_out_file

yaml_verify $hash_out_file

# Verify output as expected.
while IFS='' read -r l || [[ -n "$l" ]]; do

  alg=`echo -n $l | cut -d\: -f 1-1`
  if ! which "$alg"sum >/dev/null 2>&1; then
      echo "Ignore checking $alg algorithm due to unavailable \"${alg}sum\" program"
      continue
  fi

  hash=`echo -n $l | awk {'print $2'}`
  check=`"$alg"sum $hash_in_file | cut -d' ' -f 1-1`
  if [ "$check" != "$hash" ]; then
    echo "Hash check failed for alg \"$alg\", got \"$hash\", expected \"$check\""
    exit 1
  fi
done < $hash_out_file

tpm2_pcrlist -L sha1:9 > $yaml_out_file
old_pcr_value=`yaml_get_kv $yaml_out_file \"sha1\" 9`

# Verify that extend works, and test large files
dd if=/dev/urandom of=$hash_in_file count=1 bs=2093 2> /dev/null
tpm2_pcrevent -Q -i 9 $hash_in_file

tpm2_pcrlist -L sha1:9 > $yaml_out_file
new_pcr_value=`yaml_get_kv $yaml_out_file \"sha1\" 9`

if [ "$new_pcr_value" == "$old_pcr_value" ]; then
  echo "Expected PCR value to change after pcrevent with index 9."
  echo "Got the same hash as before: "$new_pcr_value"".
  exit 1;
fi

# verify that specifying -P without -i fails
trap - ERR

cmd="tpm2_pcrevent -Q -P foo $hash_in_file 2> /dev/null"
eval "$cmd"
if [ $? -eq 0 ]; then
  echo "Expected $cmd to fail, passed."
  exit 1;
fi

exit 0
