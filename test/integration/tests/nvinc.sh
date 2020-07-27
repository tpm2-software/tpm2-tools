# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;

source helpers.sh

nv_test_index=0x1500018

pcr_specification=sha256:0,1,2,3+sha1:0,1,2,3
file_pcr_value=pcr.bin
file_policy=policy.data

cleanup() {
  tpm2 nvundefine -Q   $nv_test_index -C o 2>/dev/null || true
  tpm2 nvundefine -Q   0x1500016 -C o 2>/dev/null || true
  tpm2 nvundefine -Q   0x1500015 -C o -P owner 2>/dev/null || true

  rm -f policy.bin test.bin nv.readlock foo.dat $file_pcr_value $file_policy \
        nv.out cap.out

  if [ "$1" != "no-shut-down" ]; then
     shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear

tpm2 nvdefine -Q   $nv_test_index -C o -s 8 \
-a "ownerread|policywrite|ownerwrite|nt=1"

tpm2 nvincrement -Q   $nv_test_index -C o

a=0x$(tpm2 nvread  $nv_test_index -C o -s 8 | xxd -p)

tpm2 nvreadpublic > nv.out
yaml_get_kv nv.out "$nv_test_index" > /dev/null

# Test writing to and reading from an offset by:
# 1. incrementing the nv counter
# 2. reading back the index
# 3. comparing the result.

tpm2 nvincrement -Q   $nv_test_index -C o

b=0x$(tpm2 nvread  $nv_test_index -C o -s 8 | xxd -p)

if [ $(($a+1)) -ne $(($b)) ]; then
 echo "Failed to increment: $(($a)) -> $(($b))."
 exit 1
fi

tpm2 nvundefine   $nv_test_index -C o


tpm2 pcrread -Q -o $file_pcr_value $pcr_specification

tpm2 createpolicy -Q --policy-pcr -l $pcr_specification \
-f $file_pcr_value -L $file_policy

tpm2 nvdefine -Q   0x1500016 -C o -s 8 -L $file_policy \
-a "policyread|policywrite|nt=1"

# Increment with index authorization for now, since tpm2 nvincrement does not
# support pcr policy.
# Counter is initialised to highest value previously seen (in this case 2) then
# incremented
tpm2 nvincrement -Q   0x1500016 -C 0x1500016 \
-P pcr:$pcr_specification=$file_pcr_value

c=0x$(tpm2 nvread  0x1500016 -C 0x1500016 -P pcr:$pcr_specification=$file_pcr_value -s 8 | xxd -p)

if [ $(($b+1)) -ne $(($c)) ]; then
 echo "Failed to increment: $(($b)) -> $(($c))."
 exit 1
fi

# this should fail because authread is not allowed
trap - ERR
tpm2 nvread   0x1500016 -C 0x1500016 -P "index" 2>/dev/null
trap onerror ERR

tpm2 nvundefine -Q   0x1500016 -C o


#
# Test NV access locked
#
tpm2 nvdefine -Q   $nv_test_index -C o -s 8 \
-a "ownerread|policywrite|ownerwrite|read_stclear|nt=1"

tpm2 nvincrement -Q   $nv_test_index -C o

tpm2 nvread -Q   $nv_test_index -C o -s 8

tpm2 nvreadlock -Q   $nv_test_index -C o

# Reset ERR signal handler to test for expected nvread error
trap - ERR

tpm2 nvread -Q   $nv_test_index -C o -s 8 2> /dev/null
if [ $? != 1 ];then
 echo "nvread didn't fail!"
 exit 1
fi

#
# Test that owner and index passwords work by
# 1. Setting up the owner password
# 2. Defining an nv index that can be satisfied by an:
#   a. Owner authorization
#   b. Index authorization
# 3. Using index and owner based auth during write/read operations
# 4. Testing that auth is needed or a failure occurs.
#
trap onerror ERR

tpm2 changeauth -c o owner

tpm2 nvdefine   0x1500015 -C o -s 8 \
  -a "policyread|policywrite|authread|authwrite|ownerwrite|ownerread|nt=1" \
  -p "index" -P "owner"

# Use index password write/read, implicit -C
tpm2 nvincrement -Q   0x1500015 -P "index"
tpm2 nvread -Q   0x1500015 -P "index"

# Use index password write/read, explicit -C
tpm2 nvincrement -Q   0x1500015 -C 0x1500015 -P "index"
tpm2 nvread -Q   0x1500015 -C 0x1500015 -P "index"

# use owner password
tpm2 nvincrement -Q   0x1500015 -C o -P "owner"
tpm2 nvread -Q   0x1500015 -C o -P "owner"

# Check a bad password fails
trap - ERR
tpm2 nvincrement -Q   0x1500015 -C 0x1500015 -P "wrong" 2>/dev/null
if [ $? -eq 0 ];then
 echo "nvincrement with bad password should fail!"
 exit 1
fi

# Check using authorisation with tpm2 nvundefine
trap onerror ERR

tpm2 nvundefine   0x1500015 -C o -P "owner"

exit 0
