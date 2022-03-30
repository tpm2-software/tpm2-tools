# SPDX-License-Identifier: BSD-3-Clause

if [ "`uname`" == "FreeBSD" ]; then
        exit 77
fi

source helpers.sh

nv_test_index=0x1500018

large_file_name="nv.test_large_w"
large_file_read_name="nv.test_large_r"

pcr_specification=sha256:0,1,2,3+sha1:0,1,2,3
file_pcr_value=pcr.bin
file_policy=policy.data

cleanup() {
  tpm2 nvundefine -Q   $nv_test_index -C o 2>/dev/null || true
  tpm2 nvundefine -Q   0x1500016 -C o 2>/dev/null || true
  tpm2 nvundefine -Q   0x1500015 -C o -P owner 2>/dev/null || true

  rm -f policy.bin test.bin nv.test_w $large_file_name $large_file_read_name \
  nv.readlock foo.dat cmp.dat $file_pcr_value $file_policy nv.out cap.out yaml.out

  if [ "$1" != "no-shut-down" ]; then
     shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear

#Test nvdefine with no options
tpm2 nvdefine > yaml.out
tpm2 nvundefine $(yaml_get_kv yaml.out "nv-index")

#Test default values for the hierarchy "-a" parameter
tpm2 nvdefine -Q   $nv_test_index -s 32 -a "ownerread|policywrite|ownerwrite"
tpm2 nvundefine -Q   $nv_test_index

#Test writing and reading
tpm2 nvdefine -Q   $nv_test_index -C o -s 32 \
-a "ownerread|policywrite|ownerwrite"

echo "please123abc" > nv.test_w

tpm2 nvwrite -Q   $nv_test_index -C o -i nv.test_w

tpm2 nvread -Q   $nv_test_index -C o -s 32 -o 0

tpm2 nvreadpublic > nv.out
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
cat foo.dat | tpm2 nvwrite -Q   $nv_test_index -C o --offset 4 -i -

tpm2 nvread   $nv_test_index -C o -s 13 > cmp.dat

cmp nv.test_w cmp.dat

# Writing at an offset and data size too big shouldn't result in a change
# to the index value.

trap - ERR

tpm2 nvwrite -Q   $nv_test_index -C o -o 30 -i foo.dat 2>/dev/null
if [ $? -eq 0 ]; then
  echo "Writing past the public size shouldn't work!"
  exit 1
fi
trap onerror ERR

tpm2 nvread   $nv_test_index -C o -s 13 > cmp.dat

cmp nv.test_w cmp.dat

tpm2 nvundefine   $nv_test_index -C o

tpm2 pcrread -Q -o $file_pcr_value $pcr_specification

tpm2 createpolicy -Q --policy-pcr -l $pcr_specification -f $file_pcr_value \
-L $file_policy

tpm2 nvdefine -Q   0x1500016 -C o -s 32 -L $file_policy \
-a "policyread|policywrite"

# Write with index authorization for now, since tpm2 nvwrite does not support
# pcr policy.
echo -n "policy locked" | tpm2 nvwrite -Q   0x1500016 -C 0x1500016 \
-P pcr:$pcr_specification=$file_pcr_value -i -

str=`tpm2 nvread   0x1500016 -C 0x1500016 \
-P pcr:$pcr_specification=$file_pcr_value -s 13`

test "policy locked" == "$str"

# this should fail because authread is not allowed
trap - ERR
tpm2 nvread   0x1500016 -C 0x1500016 -P "index" 2>/dev/null
trap onerror ERR

tpm2 nvundefine -Q   0x1500016 -C o

#
# Test large writes
#

tpm2 getcap properties-fixed > cap.out
large_file_size=`yaml_get_kv cap.out "TPM2_PT_NV_INDEX_MAX" "raw"`
nv_test_index=0x1000000

# Create an nv space with attributes 1010 = TPMA_NV_PPWRITE and
# TPMA_NV_AUTHWRITE
tpm2 nvdefine -Q   $nv_test_index -C o -s $large_file_size -a 0x2000A

base64 /dev/urandom | head -c $(($large_file_size)) > $large_file_name

# Test file input redirection
tpm2 nvwrite -Q   $nv_test_index -C o -i -< $large_file_name

tpm2 nvread   $nv_test_index -C o > $large_file_read_name

cmp -s $large_file_read_name $large_file_name

# test per-index readpublic
tpm2 nvreadpublic "$nv_test_index" > nv.out
yaml_get_kv nv.out "$nv_test_index" > /dev/null

tpm2 nvundefine -Q   $nv_test_index -C o

#
# Test NV access locked
#
tpm2 nvdefine -Q   $nv_test_index -C o -s 32 \
-a "ownerread|policywrite|ownerwrite|read_stclear|writedefine"

echo "foobar" > nv.readlock

tpm2 nvwrite -Q   $nv_test_index -C o -i nv.readlock

tpm2 nvread -Q   $nv_test_index -C o -s 6 -o 0

tpm2 nvreadlock -Q   $nv_test_index -C o

# Reset ERR signal handler to test for expected nvread error
trap - ERR

tpm2 nvread -Q   $nv_test_index -C o -s 6 -o 0 2> /dev/null
if [ $? != 1 ];then
 echo "nvread didn't fail!"
 exit 1
fi

trap onerror ERR

# Test that write lock works
tpm2 nvwritelock -C o $nv_test_index

trap - ERR

tpm2 nvwrite  $nv_test_index -C o -i nv.readlock
if [ $? != 1 ];then
 echo "nvwrite didn't fail!"
 exit 1
fi

tpm2 nvundefine -C o $nv_test_index

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

tpm2 changeauth -c o owner

tpm2 nvdefine   0x1500015 -C o -s 32 \
  -a "policyread|policywrite|authread|authwrite|ownerwrite|ownerread" \
  -p "index" -P "owner"

# Use index password write/read, implicit -a
tpm2 nvwrite -Q   0x1500015 -P "index" -i nv.test_w
tpm2 nvread -Q   0x1500015 -P "index"

# Use index password write/read, explicit -a
tpm2 nvwrite -Q   0x1500015 -C 0x1500015 -P "index" -i nv.test_w
tpm2 nvread -Q   0x1500015 -C 0x1500015 -P "index"

# use owner password
tpm2 nvwrite -Q   0x1500015 -C o -P "owner" -i nv.test_w
tpm2 nvread -Q   0x1500015 -C o -P "owner"

# Check a bad password fails
trap - ERR
tpm2 nvwrite -Q   0x1500015 -C 0x1500015 -P "wrong" -i nv.test_w 2>/dev/null
if [ $? -eq 0 ];then
 echo "nvwrite with bad password should fail!"
 exit 1
fi

# Check using authorisation with tpm2 nvundefine
trap onerror ERR

tpm2 nvundefine   0x1500015 -C o -P "owner"

# Check nv index can be specified simply as an offset
tpm2 nvdefine -Q -C o -s 32 -a "ownerread|ownerwrite" 1 -P "owner"
tpm2 nvundefine   0x01000001 -C o -P "owner"

# Test setbits
tpm2 nvdefine -C o -P "owner" -a "nt=bits|ownerread|policywrite|ownerwrite|writedefine" $nv_test_index
tpm2 nvsetbits -C o -P "owner" -i 0xbadc0de $nv_test_index
check=$(tpm2 nvread -C o -P "owner" $nv_test_index | xxd -p | sed s/'^0*'/0x/)
if [ "$check" != "0xbadc0de" ]; then
	echo "Expected setbits read value of 0xbadc0de, got \"$check\""
	exit 1
fi

# Test global writelock
if is_cmd_supported "NV_GlobalWriteLock"; then
  tpm2 nvdefine -C o -P "owner" -s 32 -a "ownerread|ownerwrite|globallock" 42
  tpm2 nvdefine -C o -P "owner" -s 32 -a "ownerread|ownerwrite|globallock" 43
  tpm2 nvdefine -C o -P "owner" -s 32 -a "ownerread|ownerwrite|globallock" 44

  echo foo | tpm2 nvwrite -C o -P "owner" -i- 42
  echo foo | tpm2 nvwrite -C o -P "owner" -i- 43
  echo foo | tpm2 nvwrite -C o -P "owner" -i- 44

  tpm2 nvwritelock -Co -P owner --global

  # These writes should fail now that its in a writelocked state
  trap - ERR
  echo foo | tpm2 nvwrite -C o -P "owner" -i- 42
  if [ $? -eq 0 ]; then
    echo "Expected tpm2 nvwrite to fail after globalwritelock of index 42"
    exit 1
  fi

  echo foo | tpm2 nvwrite -C o -P "owner" -i- 43
  if [ $? -eq 0 ]; then
    echo "Expected tpm2 nvwrite to fail after globalwritelock of index 43"
    exit 1
  fi

  echo foo | tpm2 nvwrite -C o -P "owner" -i- 44
  if [ $? -eq 0 ]; then
    echo "Expected tpm2 nvwrite to fail after globalwritelock of index 44"
    exit 1
  fi
fi

trap onerror ERR

tpm2 nvundefine -C o -P "owner" $nv_test_index

# Test extend
tpm2 nvdefine -C o -P "owner" -a "nt=extend|ownerread|policywrite|ownerwrite" $nv_test_index
echo "foo" | tpm2 nvextend -C o -P "owner" -i- $nv_test_index
check=$(tpm2 nvread -C o -P "owner" $nv_test_index | xxd -p -c 64 | sed s/'^0*'//)
expected="1c8457de84bb43c18d5e1d75c43e393bdaa7bca8d25967eedd580c912db65e3e"
if [ "$check" != "$expected" ]; then
	echo "Expected setbits read value of \"$expected\", got \"$check\""
	exit 1
fi

# Test nvextend and nvdefine with aux sessions
tpm2 clear

tpm2 createprimary -C o -c prim.ctx
tpm2 startauthsession -S enc_session.ctx --hmac-session -c prim.ctx

tpm2 changeauth -c o owner
tpm2 nvdefine -C o -P owner -a "nt=extend|ownerread|policywrite|ownerwrite" \
$nv_test_index -p nvindexauth -S enc_session.ctx

echo "foo" | tpm2 nvextend -C o -P owner -i- $nv_test_index -S enc_session.ctx

tpm2 flushcontext enc_session.ctx
rm enc_session.ctx
rm prim.ctx

check=$(tpm2 nvread -C o -P owner $nv_test_index | xxd -p -c 64 | sed s/'^0*'//)
expected="1c8457de84bb43c18d5e1d75c43e393bdaa7bca8d25967eedd580c912db65e3e"
if [ "$check" != "$expected" ]; then
	echo "Expected setbits read value of \"$expected\", got \"$check\""
	exit 1
fi

#
# Test for TPM2_NV_ReadPublic cpHash output
#
tpm2 clear
TPM2_CC_NV_ReadPublic="00000169"
tpm2 nvdefine 1
NV_INDEX_NAME=$(tpm2 nvreadpublic 1| grep name | awk {'print $2'})
tpm2 nvundefine 1
tpm2 nvreadpublic 1 --cphash cp.hash --tcti=none -n $NV_INDEX_NAME
echo -ne $TPM2_CC_NV_ReadPublic$NV_INDEX_NAME | xxd -r -p | openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2
if [ $? != 0 ]; then
	echo "cpHash doesn't match calculated value"
	exit 1
fi
tpm2 clear

# Test human readable NV counter
tpm2 nvdefine -C o -a "nt=counter|ownerread|ownerwrite" $nv_test_index
tpm2 nvincrement -C o $nv_test_index
check=$(tpm2 nvread -C o $nv_test_index --print-yaml)
expected="counter: 1"
if [ "$check" != "$expected" ]; then
    echo "Expected human readable counter value of \"$expected\", got \"$check\""
    exit 1
fi
tpm2 nvundefine -C o $nv_test_index

# Test human readable NV bits
tpm2 nvdefine -C o -a "nt=bits|ownerread|ownerwrite" $nv_test_index
tpm2 nvsetbits -C o --bits 0x4000000000000001  $nv_test_index
check=$(tpm2 nvread -C o $nv_test_index --print-yaml)
expected="bits: [ 0, 62 ]"
if [ "$check" != "$expected" ]; then
    echo "Expected human readable bits value of \"$expected\", got \"$check\""
    exit 1
fi
tpm2 nvundefine -C o $nv_test_index

# Test human readable NV extend
tpm2 nvdefine -C o -g sha256 -a "nt=extend|ownerread|ownerwrite" $nv_test_index
echo -n "falafel" | tpm2 nvextend -C o -i -  $nv_test_index
check=$(tpm2 nvread -C o $nv_test_index --print-yaml)
expected="sha256: 0xC5728723A3BB57916DB9E5DEA901094C63A960598A8A29FE277AEE5F6A8EE7CE"
if [ "$check" != "$expected" ]; then
    echo "Expected human readable extended value of \"$expected\", got \"$check\""
    exit 1
fi
tpm2 nvundefine -C o $nv_test_index

# Test human readable NV pinfail
tpm2 nvdefine -C o -g sha256 -a "nt=pinfail|ownerread|ownerwrite|no_da" $nv_test_index
echo -n "000004D20000162E" | xxd -r -p | tpm2 nvwrite -C o -i - $nv_test_index
check=$(tpm2 nvread -C o $nv_test_index --print-yaml)
expected=$(echo -e "pinfail:\n  pinCount: 1234\n  pinLimit: 5678")
if [ "$check" != "$expected" ]; then
    echo "Expected human readable extended value of \"$expected\", got \"$check\""
    exit 1
fi
tpm2 nvundefine -C o $nv_test_index

# Test human readable NV pinpass
tpm2 nvdefine -C o -g sha256 -a "nt=pinpass|ownerread|ownerwrite|no_da" $nv_test_index
echo -n "000004D20000162E" | xxd -r -p | tpm2 nvwrite -C o -i - $nv_test_index
check=$(tpm2 nvread -C o $nv_test_index --print-yaml)
expected=$(echo -e "pinpass:\n  pinCount: 1234\n  pinLimit: 5678")
if [ "$check" != "$expected" ]; then
    echo "Expected human readable extended value of \"$expected\", got \"$check\""
    exit 1
fi
tpm2 nvundefine -C o $nv_test_index

# Test human readable NV ordinary
tpm2 nvdefine -C o -g sha256 -s 4 -a "ownerread|ownerwrite" $nv_test_index
echo -n "00010203" | xxd -r -p | tpm2 nvwrite -C o -i - $nv_test_index
check=$(tpm2 nvread -C o $nv_test_index --print-yaml)
expected="data: 00010203"
if [ "$check" != "$expected" ]; then
    echo "Expected human readable extended value of \"$expected\", got \"$check\""
    exit 1
fi
tpm2 nvundefine -C o $nv_test_index

exit 0
