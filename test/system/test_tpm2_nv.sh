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

nv_test_index=0x1500018
nv_auth_handle=0x40000001

large_file_name="nv.test_large_w"
large_file_read_name="nv.test_large_r"

alg_pcr_policy=sha1
pcr_ids="0,1,2,3"
file_pcr_value=pcr.bin
file_policy=policy.data

cleanup() {
  tpm2_nvrelease -Q -x $nv_test_index -a $nv_auth_handle 2>/dev/null || true
  tpm2_nvrelease -Q -x 0x1500016 -a 0x40000001 2>/dev/null || true
  tpm2_nvrelease -Q -x 0x1500015 -a 0x40000001 -P owner 2>/dev/null || true

  rm -f policy.bin test.bin nv.test_w $large_file_name $large_file_read_name \
        nv.readlock foo.dat cmp.dat $file_pcr_value $file_policy nv.out
}

trap cleanup EXIT

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

function yaml_get() {

python << pyscript
from __future__ import print_function

import sys
import yaml

with open("$2") as f:
	try:
		y = yaml.load(f)
		found = $1 in y
		if (not found):
			sys.stderr.write('Could not find index 0x%X\n' % ($1))
		sys.exit(not found)
	except yaml.YAMLError as exc:
		sys.exit(exc)
pyscript
}

cleanup

tpm2_takeownership -c

tpm2_nvdefine -Q -x $nv_test_index -a $nv_auth_handle -s 32 -t "ownerread|policywrite|ownerwrite"

echo "please123abc" > nv.test_w

tpm2_nvwrite -Q -x $nv_test_index -a $nv_auth_handle nv.test_w

tpm2_nvread -Q -x $nv_test_index -a $nv_auth_handle -s 32 -o 0

tpm2_nvlist > nv.out
yaml_get $nv_test_index nv.out


# Test writing to and reading from an offset by:
# 1. writing "foo" into the nv file at an offset
# 2. writing to the same offset in the nv index
# 3. reading back the index
# 4. comparing the result.

echo -n "foo" > foo.dat

dd if=foo.dat of=nv.test_w bs=1 seek=4 conv=notrunc 2>/dev/null

# Test a pipe input
cat foo.dat | tpm2_nvwrite -Q -x $nv_test_index -a $nv_auth_handle -o 4

tpm2_nvread -x $nv_test_index -a $nv_auth_handle -s 13 > cmp.dat

cmp nv.test_w cmp.dat

# Writing at an offset and data size too big shouldn't result in a change
# to the index value.

trap - ERR

tpm2_nvwrite -Q -x $nv_test_index -a $nv_auth_handle -o 30 foo.dat 2>/dev/null
if [ $? -eq 0 ]; then
  echo "Writing past the public size shouldn't work!"
  exit 1
fi
trap onerror ERR

tpm2_nvread -x $nv_test_index -a $nv_auth_handle -s 13 > cmp.dat

cmp nv.test_w cmp.dat

tpm2_nvrelease -x $nv_test_index -a $nv_auth_handle  

tpm2_pcrlist -Q -L ${alg_pcr_policy}:${pcr_ids} -o $file_pcr_value

tpm2_createpolicy -Q -P -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value -f $file_policy

tpm2_nvdefine -Q -x 0x1500016 -a 0x40000001 -s 32 -L $file_policy -t "policyread|policywrite"

# Write with index authorization for now, since tpm2_nvwrite does not support pcr policy.
echo -n "policy locked" | tpm2_nvwrite -Q -x 0x1500016 -a 0x1500016 -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value

str=`tpm2_nvread -x 0x1500016 -a 0x1500016 -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value -s 13`

test "policy locked" == "$str"

# this should fail because authread is not allowed
trap - ERR
tpm2_nvread -x 0x1500016 -a 0x1500016 -P "index" 2>/dev/null
trap onerror ERR

tpm2_nvrelease -Q -x 0x1500016 -a 0x40000001

#
# Test large writes
#
large_file_size=$(tpm2_getcap -c properties-fixed | grep TPM_PT_NV_INDEX_MAX | sed -r -e 's/.*(0x[0-9a-f]+)/\1/g')
nv_test_index=0x1000000

# Create an nv space with attributes 1010 = TPMA_NV_PPWRITE and TPMA_NV_AUTHWRITE
tpm2_nvdefine -Q -x $nv_test_index -a $nv_auth_handle -s $large_file_size -t 0x2000A

base64 /dev/urandom | head -c $(($large_file_size)) > $large_file_name

# Test file input redirection
tpm2_nvwrite -Q -x $nv_test_index -a $nv_auth_handle < $large_file_name

tpm2_nvread -x $nv_test_index -a $nv_auth_handle > $large_file_read_name

cmp -s $large_file_read_name $large_file_name

tpm2_nvlist > nv.out
yaml_get $nv_test_index nv.out

tpm2_nvrelease -Q -x $nv_test_index -a $nv_auth_handle

#
# Test NV access locked
#
tpm2_nvdefine -Q -x $nv_test_index -a $nv_auth_handle -s 32 -t "ownerread|policywrite|ownerwrite|read_stclear"

echo "foobar" > nv.readlock

tpm2_nvwrite -Q -x $nv_test_index -a $nv_auth_handle nv.readlock

tpm2_nvread -Q -x $nv_test_index -a $nv_auth_handle -s 6 -o 0

tpm2_nvreadlock -Q -x $nv_test_index -a $nv_auth_handle

# Reset ERR signal handler to test for expected nvread error
trap - ERR

tpm2_nvread -Q -x $nv_test_index -a $nv_auth_handle -s 6 -o 0 2> /dev/null
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

tpm2_takeownership -o owner

tpm2_nvdefine -x 0x1500015 -a 0x40000001 -s 32 \
  -t "policyread|policywrite|authread|authwrite|ownerwrite|ownerread" \
  -I "index" -P "owner"

# Use index password write/read
tpm2_nvwrite -Q -x 0x1500015 -a 0x1500015 -P "index" nv.test_w
tpm2_nvread -Q -x 0x1500015 -a 0x1500015 -P "index"

# use owner password
tpm2_nvwrite -Q -x 0x1500015 -a 0x40000001 -P "owner" nv.test_w
tpm2_nvread -Q -x 0x1500015 -a 0x40000001 -P "owner"

# Check a bad password fails
trap - ERR
tpm2_nvwrite -Q -x 0x1500015 -a 0x1500015 -P "wrong" nv.test_w 2>/dev/null
if [ $? -eq 0 ];then
 echo "nvwrite with bad password should fail!"
 exit 1
fi

exit 0
