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
    tpm2_startauthsession -S $session_file --policy-session
  else
    tpm2_startauthsession -S $session_file
  fi
  tpm2_policycommandcode -S $session_file TPM2_CC_NV_Write
  tpm2_policynvwritten -S $session_file -L nvwrite.policy c
}

trap cleanup EXIT

start_up

cleanup "no-shutdown"

tpm2_clear

# Create a write once NV index. To do this the NV index is defined with a write
# policy that is valid only if the NV index attribute "TPMA_NV_WRITTEN" was
# never set.

#Define the NV index write policy
setup_nv_written_policy
tpm2_flushcontext $session_file

# Define the NV index with the policy
 tpm2_nvdefine -s 1 -a "authread|policywrite" -p nvrdpass -L nvwrite.policy

# Write the NV index by satisfying the policy
setup_nv_written_policy $POLICYSESSION
echo 0xAA | xxd -r -p | tpm2_nvwrite 0x01000000 -i- -P session:$session_file
tpm2_flushcontext $session_file

# Attempt writing the NV index again
setup_nv_written_policy $POLICYSESSION
trap - ERR
echo 0xAA | xxd -r -p | tpm2_nvwrite 0x01000000 -i- -P session:$session_file
if [ $? != 1 ];then
 echo "FAIL: Expected tpm2_policynvwritten to fail!"
 exit 1
fi
trap onerror ERR
tpm2_flushcontext session.dat

exit 0
