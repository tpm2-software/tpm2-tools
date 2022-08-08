# SPDX-License-Identifier: BSD-3-Clause

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

## Check cpHash output for TPM2_PCR_Event
tpm2 pcrevent 0 -Q $hash_in_file --cphash cp.hash
TPM2_CC_PCR_Event="0000013c"
pcrHandle="00000000"
size=$(printf "%04x" $(ls -l $hash_in_file | awk {'print $5'}))
file_content=$(xxd -p $hash_in_file)
Param_pcrEvent=$size$file_content

echo -ne $TPM2_CC_PCR_Event$pcrHandle$Param_pcrEvent | xxd -r -p | \
openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2

# Run FILE and stdin as FILE
tpm2 pcrevent -Q $hash_in_file
tpm2 pcrevent -Q < $hash_in_file

# Test that fifo stdin works
cat $hash_in_file | tpm2 pcrevent > $hash_out_file

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

tpm2 pcrread sha1:9 > $yaml_out_file
old_pcr_value=`yaml_get_kv $yaml_out_file "sha1" "9"`

# Verify that extend works, and test large files
dd if=/dev/urandom of=$hash_in_file count=1 bs=2093 2> /dev/null
tpm2 pcrevent -Q 9 $hash_in_file

tpm2 pcrread sha1:9 > $yaml_out_file
new_pcr_value=`yaml_get_kv $yaml_out_file "sha1" "9"`

if [ "$new_pcr_value" == "$old_pcr_value" ]; then
  echo "Expected PCR value to change after pcrevent with index 9."
  echo "Got the same hash as before: "$new_pcr_value"".
  exit 1;
fi

# verify that specifying -P without -i fails
trap - ERR

cmd="tpm2 pcrevent -Q -P foo $hash_in_file 2> /dev/null"
eval "$cmd"
if [ $? -eq 0 ]; then
  echo "Expected $cmd to fail, passed."
  exit 1;
fi

exit 0
