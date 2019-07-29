# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

nv_test_index=0x1500018

large_file_name="nv.test_large_w"
large_file_read_name="nv.test_large_r"

alg_pcr_policy=sha1
pcr_ids="0,1,2,3"
file_pcr_value=pcr.bin
file_policy=policy.data

cleanup() {
  tpm2_nvundefine -Q   $nv_test_index -C o 2>/dev/null || true
  tpm2_nvundefine -Q   0x1500016 -C 0x40000001 2>/dev/null || true
  tpm2_nvundefine -Q   0x1500015 -C 0x40000001 -P owner 2>/dev/null || true

  rm -f policy.bin test.bin nv.test_w $large_file_name $large_file_read_name \
        nv.readlock foo.dat cmp.dat $file_pcr_value $file_policy nv.out cap.out

  if [ "$1" != "no-shut-down" ]; then
     shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear

#Test default values for the hierarchy "-a" parameter
tpm2_nvdefine -Q   $nv_test_index -s 32 -a "ownerread|policywrite|ownerwrite"
tpm2_nvundefine -Q   $nv_test_index

#Test writing and reading
tpm2_nvdefine -Q   $nv_test_index -C o -s 32 -a "ownerread|policywrite|ownerwrite"

echo "please123abc" > nv.test_w

tpm2_nvwrite -Q   $nv_test_index -C o -i nv.test_w

tpm2_nvread -Q   $nv_test_index -C o -s 32 -o 0

tpm2_nvreadpublic > nv.out
yaml_get_kv nv.out "$nv_test_index" > /dev/null


# Test writing to and reading from an offset by:
# 1. writing "foo" into the nv file at an offset
# 2. writing to the same offset in the nv index
# 3. reading back the index
# 4. comparing the result.

echo -n "foo" > foo.dat

dd if=foo.dat of=nv.test_w bs=1 seek=4 conv=notrunc 2>/dev/null

# Test a pipe input
cat foo.dat | tpm2_nvwrite -Q   $nv_test_index -C o --offset 4 -i -

tpm2_nvread   $nv_test_index -C o -s 13 > cmp.dat

cmp nv.test_w cmp.dat

# Writing at an offset and data size too big shouldn't result in a change
# to the index value.

trap - ERR

tpm2_nvwrite -Q   $nv_test_index -C o -o 30 -i foo.dat 2>/dev/null
if [ $? -eq 0 ]; then
  echo "Writing past the public size shouldn't work!"
  exit 1
fi
trap onerror ERR

tpm2_nvread   $nv_test_index -C o -s 13 > cmp.dat

cmp nv.test_w cmp.dat

tpm2_nvundefine   $nv_test_index -C o

tpm2_pcrlist -Q -o $file_pcr_value ${alg_pcr_policy}:${pcr_ids}

tpm2_createpolicy -Q --policy-pcr -l ${alg_pcr_policy}:${pcr_ids} -f $file_pcr_value -L $file_policy

tpm2_nvdefine -Q   0x1500016 -C 0x40000001 -s 32 -L $file_policy -a "policyread|policywrite"

# Write with index authorization for now, since tpm2_nvwrite does not support pcr policy.
echo -n "policy locked" | tpm2_nvwrite -Q   0x1500016 -C 0x1500016 -P pcr:${alg_pcr_policy}:${pcr_ids}+$file_pcr_value -i -

str=`tpm2_nvread   0x1500016 -C 0x1500016 -P pcr:${alg_pcr_policy}:${pcr_ids}+$file_pcr_value -s 13`

test "policy locked" == "$str"

# this should fail because authread is not allowed
trap - ERR
tpm2_nvread   0x1500016 -C 0x1500016 -P "index" 2>/dev/null
trap onerror ERR

tpm2_nvundefine -Q   0x1500016 -C 0x40000001

#
# Test large writes
#

tpm2_getcap properties-fixed > cap.out
large_file_size=`yaml_get_kv cap.out "TPM2_PT_NV_INDEX_MAX" "raw"`
nv_test_index=0x1000000

# Create an nv space with attributes 1010 = TPMA_NV_PPWRITE and TPMA_NV_AUTHWRITE
tpm2_nvdefine -Q   $nv_test_index -C o -s $large_file_size -a 0x2000A

base64 /dev/urandom | head -c $(($large_file_size)) > $large_file_name

# Test file input redirection
tpm2_nvwrite -Q   $nv_test_index -C o -i -< $large_file_name

tpm2_nvread   $nv_test_index -C o > $large_file_read_name

cmp -s $large_file_read_name $large_file_name

tpm2_nvreadpublic > nv.out
yaml_get_kv nv.out "$nv_test_index" > /dev/null

tpm2_nvundefine -Q   $nv_test_index -C o

#
# Test NV access locked
#
tpm2_nvdefine -Q   $nv_test_index -C o -s 32 -a "ownerread|policywrite|ownerwrite|read_stclear"

echo "foobar" > nv.readlock

tpm2_nvwrite -Q   $nv_test_index -C o -i nv.readlock

tpm2_nvread -Q   $nv_test_index -C o -s 6 -o 0

tpm2_nvreadlock -Q   $nv_test_index -C o

# Reset ERR signal handler to test for expected nvread error
trap - ERR

tpm2_nvread -Q   $nv_test_index -C o -s 6 -o 0 2> /dev/null
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

tpm2_changeauth -c o owner

tpm2_nvdefine   0x1500015 -C 0x40000001 -s 32 \
  -a "policyread|policywrite|authread|authwrite|ownerwrite|ownerread" \
  -p "index" -P "owner"

# Use index password write/read, implicit -a
tpm2_nvwrite -Q   0x1500015 -P "index" -i nv.test_w
tpm2_nvread -Q   0x1500015 -P "index"

# Use index password write/read, explicit -a
tpm2_nvwrite -Q   0x1500015 -C 0x1500015 -P "index" -i nv.test_w
tpm2_nvread -Q   0x1500015 -C 0x1500015 -P "index"

# use owner password
tpm2_nvwrite -Q   0x1500015 -C 0x40000001 -P "owner" -i nv.test_w
tpm2_nvread -Q   0x1500015 -C 0x40000001 -P "owner"

# Check a bad password fails
trap - ERR
tpm2_nvwrite -Q   0x1500015 -C 0x1500015 -P "wrong" -i nv.test_w 2>/dev/null
if [ $? -eq 0 ];then
 echo "nvwrite with bad password should fail!"
 exit 1
fi

# Check using authorisation with tpm2_nvundefine
trap onerror ERR

tpm2_nvundefine   0x1500015 -C 0x40000001 -P "owner"

# Check nv index can be specified simply as an offset
tpm2_nvdefine -Q -C o -s 32 -a "ownerread|ownerwrite"   1 -P "owner"
tpm2_nvundefine   0x01000001 -C o -P "owner"

exit 0
