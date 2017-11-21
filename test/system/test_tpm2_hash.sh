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

#this script is for hash case testing 

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

ticket_file=ticket.out
hash_out_file=hash.out
hash_in_file=hash.in

cleanup() {
  rm -f $ticket_file $hash_out_file $hash_in_file
}
trap cleanup EXIT

cleanup

echo "T0naX0u123abc" > $hash_in_file

# Test with ticket and hash output files and verify that the output hash
# is correct. Ticket is not stable and changes run to run, don't verify it.
tpm2_hash -H e -g sha1 -o $hash_out_file -t $ticket_file $hash_in_file 1>/dev/null

expected=`sha1sum $hash_in_file | awk '{print $1}'`
actual=`cat $hash_out_file | xxd -p -c 20`

test "$expected" == "$actual"

cleanup

# Test platform hierarchy with multiple files and verify output against sha256sum
# Test a file redirection as well.
echo "T0naX0u123abc" > $hash_in_file
tpm2_hash -H p -g sha256 -Q -o $hash_out_file -t $ticket_file < $hash_in_file

expected=`sha256sum $hash_in_file | awk '{print $1}'`
actual=`cat $hash_out_file | xxd -p -c 256`

test "$expected" == "$actual"

cleanup

# Test stdout output as well as no options.
# Validate that hash outputs are as expected.
tpm_hash_val=`echo 1234 | tpm2_hash | grep hash | cut -d\: -f 2-2 | tr -d '[:space:]'`
sha1sum_val=`echo 1234 | sha1sum  | cut -d\  -f 1-2 | tr -d '[:space:]'`
if [ "$tpm_hash_val" != "$sha1sum_val" ]; then
  echo "Expected tpm and sha1sum to produce same hashes."
  echo "Got:"
  echo "  tpm2_hash: $tpm_hash_val"
  echo "  sha1sum:   $sha1sum_val"
  exit 1
fi

# Test a file that cannot be done in 1 update call. The tpm works on a 1024 block size.
dd if=/dev/urandom of=$hash_in_file bs=2093 count=1 2>/dev/null
tpm_hash_val=`tpm2_hash $hash_in_file | grep hash | cut -d\: -f 2-2 | tr -d '[:space:]'`
sha1sum_val=`sha1sum $hash_in_file | cut -d\  -f 1-2 | tr -d '[:space:]'`
if [ "$tpm_hash_val" != "$sha1sum_val" ]; then
  echo "Expected tpm and sha1sum to produce same hashes"
  echo "Got:"
  echo "  tpm2_hash: $tpm_hash_val"
  echo "  sha1sum:   $sha1sum_val"
  exit 1
fi

exit 0
