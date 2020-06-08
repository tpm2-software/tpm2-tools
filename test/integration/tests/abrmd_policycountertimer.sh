# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

  rm -f session.ctx prim.ctx key.pub key.priv key.ctx policy.countertimer.minute

  if [ "$1" != "no-shut-down" ]; then
     shut_down
  fi
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear

#
# Create a sealing object with a policy that evaluates for first minute after
# TPM restart. NOTE the time is 60000 milliseconds.
#
tpm2 startauthsession -S session.ctx

tpm2 policycountertimer -S session.ctx -L policy.countertimer.minute --ult \
60000

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

tpm2 policycountertimer -S session.ctx -L policy.countertimer.minute --ult \
60000

tpm2 unseal -c key.ctx -p session:session.ctx

tpm2 flushcontext session.ctx

#
# Test if a policycountertimer evaluates with the clock
#
tpm2 clear
tpm2 startauthsession -S session.ctx --policy-session
tpm2 policycountertimer -S session.ctx --ult clock=60000
tpm2 flushcontext session.ctx

#
# Test if a policycountertimer evaluates with the TPM clocks safe flag
# Assuming the safe flag is set since with just started and cleared the TPM
#
tpm2 clear
tpm2 startauthsession -S session.ctx --policy-session
tpm2 policycountertimer -S session.ctx safe
tpm2 flushcontext session.ctx

#
# Test if a policycountertimer evaluates with the TPM reset count
# Assuming the value is zero since we just cleared the TPM
#
tpm2 clear
tpm2 startauthsession -S session.ctx --policy-session
tpm2 policycountertimer -S session.ctx resets=0
tpm2 flushcontext session.ctx

#
# Test if a policycountertimer evaluates with the TPM restart count
# Assuming the value is zero since we just cleared the TPM
#
tpm2 clear
tpm2 startauthsession -S session.ctx --policy-session
tpm2 policycountertimer -S session.ctx restarts=0
tpm2 flushcontext session.ctx

exit 0
