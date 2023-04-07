# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

  rm -f session.ctx prim.ctx key.pub key.priv key.ctx policy.countertimer.minute

  if [ "$1" != "no-shut-down" ]; then
     shut_down
  fi
}

call_policy_countertimer () {
    trap - ERR
    output=$(tpm2 policycountertimer $@ 2>&1)
    result=$?

    if [ $result != 0 ] && echo $output | grep "ErrorCode.*0126" > /dev/null
    then
        echo "This test failed due to a TPM bug regarding signed comparison as described"
        echo "in TCG's Errata for TCG Trusted Platform Module Library Revision 1.59 Version 1.4,"
        echo "Section 2.5 TPM_EO – two’s complement"
        tpm2 flushcontext session.ctx
        skip_test
    else
        if [ $result != 0 ]; then
            tpm2 flushcontext session.ctx
            exit 1
        fi
    fi
    trap onerror ERR
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

## Check cpHash output for TPM2_PolicyCounterTimer
tpm2 startauthsession -S session.ctx
call_policy_countertimer -S session.ctx -L policy.countertimer.minute --ult 60000 --cphash cp.hash
TPM2_CC_PolicyCounterTimer="0000016d"
operandB="0008000000000000ea60"
offset="0000"
operation="0005"
policySession=$(tpm2 sessionconfig session.ctx | grep Session-Handle | \
  awk -F ' 0x' '{print $2}')

echo -ne $TPM2_CC_PolicyCounterTimer$policySession$operandB$offset$operation \
  | xxd -r -p | openssl dgst -sha256 -binary -out test.bin
xxd cp.hash
xxd test.bin
cmp cp.hash test.bin 2
tpm2 flushcontext session.ctx

tpm2 clear

#
# Create a sealing object with a policy that evaluates for first minute after
# TPM restart. NOTE the time is 60000 milliseconds.
#
tpm2 startauthsession -S session.ctx

call_policy_countertimer -S session.ctx -L policy.countertimer.minute --ult 60000

tpm2 flushcontext session.ctx

tpm2 createprimary -C o -c prim.ctx -Q

echo "SUPERSECRET" | \
tpm2 create -Q -u key.pub -r key.priv -i- -C prim.ctx \
-L policy.countertimer.minute -a "fixedtpm|fixedparent" -c key.ctx

#
# ASSUMING 1 minute hasn't elapsed since clear, Try unseal in the first minute
# -- Should pass
#
tpm2 startauthsession -S session.ctx --policy-session

call_policy_countertimer -S session.ctx -L policy.countertimer.minute --ult 60000

tpm2 unseal -c key.ctx -p session:session.ctx

tpm2 flushcontext session.ctx

#
# Test if a policycountertimer evaluates with the clock
#
tpm2 clear
tpm2 startauthsession -S session.ctx --policy-session
call_policy_countertimer -S session.ctx --ult clock=60000
tpm2 flushcontext session.ctx

#
# Test if a policycountertimer evaluates with the TPM clocks safe flag
# Assuming the safe flag is set since with just started and cleared the TPM
#
tpm2 clear
tpm2 startauthsession -S session.ctx --policy-session
call_policy_countertimer -S session.ctx safe
tpm2 flushcontext session.ctx

#
# Test if a policycountertimer evaluates with the TPM reset count
# Assuming the value is zero since we just cleared the TPM
#
tpm2 clear
tpm2 startauthsession -S session.ctx --policy-session
call_policy_countertimer -S session.ctx resets=0
tpm2 flushcontext session.ctx

#
# Test if a policycountertimer evaluates with the TPM restart count
# Assuming the value is zero since we just cleared the TPM
#
tpm2 clear
tpm2 startauthsession -S session.ctx --policy-session
call_policy_countertimer -S session.ctx restarts=0
tpm2 flushcontext session.ctx

exit 0
