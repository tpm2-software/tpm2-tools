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

# Test with ticket and hash output files (binary) and verify that the output
# hash is correct. Ticket is not stable and changes run to run, don't verify it.
tpm2 hash -C e -g sha1 -o $hash_out_file -t $ticket_file $hash_in_file

expected=`shasum -a 1 $hash_in_file | awk '{print $1}'`
actual=`cat $hash_out_file | xxd -p -c 20`

test "$expected" == "$actual"

cleanup "no-shut-down"

# Test platform hierarchy with multiple files & verify output against sha256sum
# Test a file redirection as well. Output files are binary.
echo "T0naX0u123abc" > $hash_in_file
tpm2 hash -C p -g sha256 -o $hash_out_file -t $ticket_file < $hash_in_file

expected=`shasum -a 256 $hash_in_file | awk '{print $1}'`
actual=`cat $hash_out_file | xxd -p -c 32`

test "$expected" == "$actual"

cleanup "no-shut-down"

# Test stdout output as well as no options.
# Validate that hash outputs are in hex as expected.
tpm_hash_val=`echo 1234 | tpm2 hash -C n --hex`
sha1sum_val=`echo 1234 | shasum -a 1  | cut -d\  -f 1-2 | tr -d '[:space:]'`
if [ "$tpm_hash_val" != "$sha1sum_val" ]; then
  echo "Expected tpm and sha1sum to produce same hashes."
  echo "Got:"
  echo "  tpm2 hash: $tpm_hash_val"
  echo "  sha1sum:   $sha1sum_val"
  exit 1
fi

# Test a file that cannot be done in 1 update call.
# The tpm works on a 1024 block size.
dd if=/dev/urandom of=$hash_in_file bs=2093 count=1 2>/dev/null
tpm_hash_val=`tpm2 hash --hex $hash_in_file`
sha1sum_val=`shasum -a 1 $hash_in_file | cut -d\  -f 1-2 | tr -d '[:space:]'`
if [ "$tpm_hash_val" != "$sha1sum_val" ]; then
  echo "Expected tpm and sha1sum to produce same hashes"
  echo "Got:"
  echo "  tpm2 hash: $tpm_hash_val"
  echo "  sha1sum:   $sha1sum_val"
  exit 1
fi

exit 0
