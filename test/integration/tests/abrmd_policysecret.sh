# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

TPM_RH_OWNER=0x40000001
SEALED_SECRET=SEALED-SECRET
session_ctx=session.ctx
o_policy_digest=policy.digest
primary_ctx=prim.ctx
seal_key_pub=sealing_key.pub
seal_key_priv=sealing_key.priv
seal_key_ctx=sealing_key.ctx

cleanup() {
    rm -f $session_ctx $o_policy_digest $primary_ctx $seal_key_pub $seal_key_priv\
    $seal_key_ctx qual.dat

    tpm2 flushcontext $session_ctx 2>/dev/null || true

    tpm2 clear

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

tpm2 clear

tpm2 changeauth -c o ownerauth

# Create Policy
tpm2 startauthsession -S $session_ctx
tpm2 policysecret -S $session_ctx -c $TPM_RH_OWNER -L $o_policy_digest ownerauth
tpm2 flushcontext $session_ctx
rm $session_ctx

# Create and Load Object
tpm2 createprimary -Q -C o -c $primary_ctx -P ownerauth
tpm2 create -Q -g sha256 -u $seal_key_pub -r $seal_key_priv -C $primary_ctx \
-L $o_policy_digest -i- <<< $SEALED_SECRET
tpm2 load -C $primary_ctx -u $seal_key_pub -r $seal_key_priv -c $seal_key_ctx

# Satisfy policy and unseal data
tpm2 startauthsession --policy-session -S $session_ctx
echo -n "ownerauth" | tpm2 policysecret -S $session_ctx -c $TPM_RH_OWNER \
-L $o_policy_digest file:-
unsealed=`tpm2 unseal -p"session:$session_ctx" -c $seal_key_ctx`
tpm2 flushcontext $session_ctx
rm $session_ctx

test "$unsealed" == "$SEALED_SECRET"

if [ $? != 0 ]; then
  echo "Failed policysecret integration test where ref object password was set."
fi

#Test the policy with auth reference object password not set
unsealed=""
tpm2 changeauth -c o -p ownerauth

tpm2 startauthsession --policy-session -S $session_ctx
tpm2 policysecret -S $session_ctx -c $TPM_RH_OWNER -L $o_policy_digest
unsealed=`tpm2 unseal -p"session:$session_ctx" -c $seal_key_ctx`
tpm2 flushcontext $session_ctx
rm $session_ctx

test "$unsealed" == "$SEALED_SECRET"

if [ $? != 0 ]; then
  echo "Failed policysecret integration test for passwordless reference object."
fi

#
# Test with policyref or qualification data
#
unsealed=""
tpm2 clear

dd if=/dev/urandom of=qual.dat bs=1 count=32
tpm2 startauthsession -S $session_ctx
tpm2 policysecret -S $session_ctx -c $TPM_RH_OWNER -L $o_policy_digest \
-q qual.dat
tpm2 flushcontext $session_ctx

tpm2 createprimary -Q -C o -c $primary_ctx
tpm2 create -Q -g sha256 -u $seal_key_pub -r $seal_key_priv -C $primary_ctx \
-L $o_policy_digest -i- <<< $SEALED_SECRET
tpm2 load -C $primary_ctx -u $seal_key_pub -r $seal_key_priv -c $seal_key_ctx

tpm2 startauthsession --policy-session -S $session_ctx
tpm2 policysecret -S $session_ctx -c $TPM_RH_OWNER -L $o_policy_digest \
-q qual.dat
unsealed=`tpm2 unseal -p"session:$session_ctx" -c $seal_key_ctx`
tpm2 flushcontext $session_ctx

test "$unsealed" == "$SEALED_SECRET"

if [ $? != 0 ]; then
  echo "Failed policysecret integration test for passwordless reference object."
fi

#
# Test with policy auth reference instead of plain password
#
tpm2 startauthsession -S session.ctx
tpm2 policyauthvalue -S session.ctx -L policy.authval
tpm2 flushcontext session.ctx
tpm2 setprimarypolicy -C o -L policy.authval -g sha256
tpm2 startauthsession -S session.ctx --policy-session
tpm2 startauthsession -S policy_session.ctx --policy-session
tpm2 policyauthvalue -S session.ctx
tpm2 policysecret -S policy_session.ctx -c o session:session.ctx
tpm2 flushcontext session.ctx
tpm2 flushcontext policy_session.ctx

exit 0
