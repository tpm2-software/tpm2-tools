# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

nv_test_index=0x1500018

large_file_name="nv.test_large_w"
large_file_read_name="nv.test_large_r"

pcr_specification=sha256:0,1,2,3+sha1:0,1,2,3
file_pcr_value=pcr.bin
file_policy=policy.data

cleanup() {
  tpm2_nvundefine -Q   $nv_test_index -C o 2>/dev/null || true
  tpm2_nvundefine -Q   0x1500016 -C 0x40000001 2>/dev/null || true
  tpm2_nvundefine -Q   0x1500015 -C 0x40000001 -P owner 2>/dev/null || true

  rm -f policy.bin test.bin nv.test_w $large_file_name $large_file_read_name \
  nv.readlock foo.dat cmp.dat $file_pcr_value $file_policy nv.out cap.out yaml.out

  if [ "$1" != "no-shut-down" ]; then
     shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear

#Test nvdefine with no options
tpm2_nvdefine > yaml.out
tpm2_nvundefine $(yaml_get_kv yaml.out "nv-index")

#Test default values for the hierarchy "-a" parameter
tpm2_nvdefine -Q   $nv_test_index -s 32 -a "ownerread|policywrite|ownerwrite"
tpm2_nvundefine -Q   $nv_test_index

#Test writing and reading
tpm2_nvdefine -Q   $nv_test_index -C o -s 32 \
-a "ownerread|policywrite|ownerwrite"

echo "please123abc" > nv.test_w

tpm2_nvwrite -Q   $nv_test_index -C o -i nv.test_w

tpm2_nvread -Q   $nv_test_index -C o -s 32 -o 0

tpm2_nvreadpublic > nv.out
yaml_get_kv nv.out "$nv_test_index" > /dev/null
yaml_get_kv nv.out "$nv_test_index" "name" > /dev/null


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

tpm2_pcrread -Q -o $file_pcr_value $pcr_specification

tpm2_createpolicy -Q --policy-pcr -l $pcr_specification -f $file_pcr_value \
-L $file_policy

tpm2_nvdefine -Q   0x1500016 -C 0x40000001 -s 32 -L $file_policy \
-a "policyread|policywrite"

# Write with index authorization for now, since tpm2_nvwrite does not support
# pcr policy.
echo -n "policy locked" | tpm2_nvwrite -Q   0x1500016 -C 0x1500016 \
-P pcr:$pcr_specification=$file_pcr_value -i -

str=`tpm2_nvread   0x1500016 -C 0x1500016 \
-P pcr:$pcr_specification=$file_pcr_value -s 13`

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

# Create an nv space with attributes 1010 = TPMA_NV_PPWRITE and
# TPMA_NV_AUTHWRITE
tpm2_nvdefine -Q   $nv_test_index -C o -s $large_file_size -a 0x2000A

base64 /dev/urandom | head -c $(($large_file_size)) > $large_file_name

# Test file input redirection
tpm2_nvwrite -Q   $nv_test_index -C o -i -< $large_file_name

tpm2_nvread   $nv_test_index -C o > $large_file_read_name

cmp -s $large_file_read_name $large_file_name

# test per-index readpublic
tpm2_nvreadpublic "$nv_test_index" > nv.out
yaml_get_kv nv.out "$nv_test_index" > /dev/null

tpm2_nvundefine -Q   $nv_test_index -C o

#
# Test NV access locked
#
tpm2_nvdefine -Q   $nv_test_index -C o -s 32 \
-a "ownerread|policywrite|ownerwrite|read_stclear|writedefine"

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

trap onerror ERR

# Test that write lock works
tpm2_nvwritelock -C o $nv_test_index

trap - ERR

tpm2_nvwrite  $nv_test_index -C o -i nv.readlock
if [ $? != 1 ];then
 echo "nvwrite didn't fail!"
 exit 1
fi

tpm2_nvundefine -C o $nv_test_index

trap onerror ERR

#
# Test that owner and index passwords work by
# 1. Setting up the owner password
# 2. Defining an nv index that can be satisfied by an:
#   a. Owner authorization
#   b. Index authorization
# 3. Using index and owner based auth during write/read operations
# 4. Testing that auth is needed or a failure occurs.
#

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
tpm2_nvdefine -Q -C o -s 32 -a "ownerread|ownerwrite" 1 -P "owner"
tpm2_nvundefine   0x01000001 -C o -P "owner"

# Test setbits
tpm2_nvdefine -C o -P "owner" -a "nt=bits|ownerread|policywrite|ownerwrite|writedefine" $nv_test_index
tpm2_nvsetbits -C o -P "owner" -i 0xbadc0de $nv_test_index
check=$(tpm2_nvread -C o -P "owner" $nv_test_index | xxd -p | sed s/'^0*'/0x/)
if [ "$check" != "0xbadc0de" ]; then
	echo "Expected setbits read value of 0xbadc0de, got \"$check\""
	exit 1
fi

# Test global writelock
if is_cmd_supported "NV_GlobalWriteLock"; then
  tpm2_nvdefine -C o -P "owner" -s 32 -a "ownerread|ownerwrite|globallock" 42
  tpm2_nvdefine -C o -P "owner" -s 32 -a "ownerread|ownerwrite|globallock" 43
  tpm2_nvdefine -C o -P "owner" -s 32 -a "ownerread|ownerwrite|globallock" 44

  echo foo | tpm2_nvwrite -C o -P "owner" -i- 42
  echo foo | tpm2_nvwrite -C o -P "owner" -i- 43
  echo foo | tpm2_nvwrite -C o -P "owner" -i- 44

  tpm2_nvwritelock -Co -P owner --global

  # These writes should fail now that its in a writelocked state
  trap - ERR
  echo foo | tpm2_nvwrite -C o -P "owner" -i- 42
  if [ $? -eq 0 ]; then
    echo "Expected tpm2_nvwrite to fail after globalwritelock of index 42"
    exit 1
  fi

  echo foo | tpm2_nvwrite -C o -P "owner" -i- 43
  if [ $? -eq 0 ]; then
    echo "Expected tpm2_nvwrite to fail after globalwritelock of index 43"
    exit 1
  fi

  echo foo | tpm2_nvwrite -C o -P "owner" -i- 44
  if [ $? -eq 0 ]; then
    echo "Expected tpm2_nvwrite to fail after globalwritelock of index 44"
    exit 1
  fi
fi

trap onerror ERR

tpm2_nvundefine -C o -P "owner" $nv_test_index

# Test extend
tpm2_nvdefine -C o -P "owner" -a "nt=extend|ownerread|policywrite|ownerwrite" $nv_test_index
echo "foo" | tpm2_nvextend -C o -P "owner" -i- $nv_test_index
check=$(tpm2_nvread -C o -P "owner" $nv_test_index | xxd -p -c 64 | sed s/'^0*'//)
expected="1c8457de84bb43c18d5e1d75c43e393bdaa7bca8d25967eedd580c912db65e3e"
if [ "$check" != "$expected" ]; then
	echo "Expected setbits read value of \"$expected\", got \"$check\""
	exit 1
fi

exit 0
