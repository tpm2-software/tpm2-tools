# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

POLICYSESSION=1
session_file=session.dat

cleanup() {
    rm -f $session_file nvwrite.policy

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}

setup_nv_written_policy() {
  if [ $1 == $POLICYSESSION ];then
    tpm2 startauthsession -S $session_file --policy-session
  else
    tpm2 startauthsession -S $session_file
  fi
  tpm2 policycommandcode -S $session_file TPM2_CC_NV_Write
  tpm2 policynvwritten -S $session_file -L nvwrite.policy c
}

trap cleanup EXIT

start_up

cleanup "no-shutdown"

## Check cpHash output for TPM2_PolicyNvWritten
tpm2 startauthsession -S $session_file
tpm2 policycommandcode -S $session_file TPM2_CC_NV_Write
tpm2 policynvwritten -S $session_file -L nvwrite.policy c --cphash cp.hash
TPM2_CC_PolicyNvWritten="0000018f"
writtenSet="00"
policySession=$(tpm2 sessionconfig session.dat | grep Session-Handle | \
    awk -F ' 0x' '{print $2}')

echo -ne $TPM2_CC_PolicyNvWritten$policySession$writtenSet | xxd -r -p | \
openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2
tpm2 flushcontext $session_file

tpm2 clear

# Create a write once NV index. To do this the NV index is defined with a write
# policy that is valid only if the NV index attribute "TPMA_NV_WRITTEN" was
# never set.

#Define the NV index write policy
setup_nv_written_policy
tpm2 flushcontext $session_file

# Define the NV index with the policy
 tpm2 nvdefine -s 1 -a "authread|policywrite" -p nvrdpass -L nvwrite.policy

# Write the NV index by satisfying the policy
setup_nv_written_policy $POLICYSESSION
echo 0xAA | xxd -r -p | tpm2 nvwrite 0x01000000 -i- -P session:$session_file
tpm2 flushcontext $session_file

# Attempt writing the NV index again
setup_nv_written_policy $POLICYSESSION
trap - ERR
echo 0xAA | xxd -r -p | tpm2 nvwrite 0x01000000 -i- -P session:$session_file
if [ $? != 1 ];then
 echo "FAIL: Expected tpm2 policynvwritten to fail!"
 exit 1
fi
trap onerror ERR
tpm2 flushcontext session.dat

exit 0
