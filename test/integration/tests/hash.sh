#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

#this script is for hash case testing

source helpers.sh

ticket_file=ticket.out
hash_out_file=hash.out
hash_in_file=hash.in
out=out.yaml

cleanup() {
  rm -f $ticket_file $hash_out_file $hash_in_file $out

  if [ "$1" != "no-shut-down" ]; then
      shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo "T0naX0u123abc" > $hash_in_file

# Test with ticket and hash output files and verify that the output hash
# is correct. Ticket is not stable and changes run to run, don't verify it.
tpm2_hash -a e -g sha1 -o $hash_out_file -t $ticket_file $hash_in_file 1>/dev/null

expected=`sha1sum $hash_in_file | awk '{print $1}'`
actual=`cat $hash_out_file | xxd -p -c 20`

test "$expected" == "$actual"

cleanup "no-shut-down"

# Test platform hierarchy with multiple files and verify output against sha256sum
# Test a file redirection as well.
echo "T0naX0u123abc" > $hash_in_file
tpm2_hash -a p -g sha256 -Q -o $hash_out_file -t $ticket_file < $hash_in_file

expected=`sha256sum $hash_in_file | awk '{print $1}'`
actual=`cat $hash_out_file | xxd -p -c 32`

test "$expected" == "$actual"

cleanup "no-shut-down"

# Test stdout output as well as no options.
# Validate that hash outputs are as expected.
tpm_hash_val=`echo 1234 | tpm2_hash -a n | tee $out | grep sha1 | cut -d\: -f 2-2 | tr -d '[:space:]'`
sha1sum_val=`echo 1234 | sha1sum  | cut -d\  -f 1-2 | tr -d '[:space:]'`
if [ "$tpm_hash_val" != "$sha1sum_val" ]; then
  echo "Expected tpm and sha1sum to produce same hashes."
  echo "Got:"
  echo "  tpm2_hash: $tpm_hash_val"
  echo "  sha1sum:   $sha1sum_val"
  exit 1
fi

# Verify the yaml output
yaml_verify $out

# Test a file that cannot be done in 1 update call. The tpm works on a 1024 block size.
dd if=/dev/urandom of=$hash_in_file bs=2093 count=1 2>/dev/null
tpm_hash_val=`tpm2_hash $hash_in_file | grep sha1 | cut -d\: -f 2-2 | tr -d '[:space:]'`
sha1sum_val=`sha1sum $hash_in_file | cut -d\  -f 1-2 | tr -d '[:space:]'`
if [ "$tpm_hash_val" != "$sha1sum_val" ]; then
  echo "Expected tpm and sha1sum to produce same hashes"
  echo "Got:"
  echo "  tpm2_hash: $tpm_hash_val"
  echo "  sha1sum:   $sha1sum_val"
  exit 1
fi

exit 0
