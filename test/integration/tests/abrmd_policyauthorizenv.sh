# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

nv_test_index=0x01500001

cleanup() {
  tpm2_nvundefine -Q -C o $nv_test_index 2>/dev/null || true
  tpm2_flushcontext -t
  tpm2_flushcontext -l
  tpm2_flushcontext -s

  rm -f session.ctx policy.pass policyauthorizenv.1500001 prim.ctx key.pub \
  key.priv key.ctx policy.pcr0

  if [ "$1" != "no-shut-down" ]; then
     shut_down
  fi
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear

# Define the test NV Index to store the auth policy
tpm2_nvdefine -C o -p nvpass $nv_test_index -a "authread|authwrite" -s 34

# Define the auth policy
tpm2_startauthsession -S session.ctx
tpm2_policypassword -S session.ctx -L policy.pass
tpm2_flushcontext session.ctx

# Write the auth policy to the NV Index
POLICYDIGESTALGORITHM=000b
echo $POLICYDIGESTALGORITHM | xxd -p -r | cat - policy.pass | \
tpm2_nvwrite -C $nv_test_index -P nvpass $nv_test_index -i-

# Define the policyauthorizenv
tpm2_startauthsession -S session.ctx
tpm2_policyauthorizenv -S session.ctx -C $nv_test_index -P nvpass \
-L policyauthorizenv.1500001 $nv_test_index
tpm2_flushcontext session.ctx

# Create and load a sealing object with auth policy = policyauthorizenv
tpm2_createprimary -C o -c prim.ctx

echo "secretdata" | \
tpm2_create -C prim.ctx -u key.pub -r key.priv \
-a "fixedtpm|fixedparent|adminwithpolicy" -L policyauthorizenv.1500001 -i-

tpm2_load -C prim.ctx -u key.pub -r key.priv -c key.ctx

# Satisfy the auth policy stored in the NV Index and thus policyauthorizenv
# And attempt user operation UNSEAL
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policypassword -S session.ctx
tpm2_policyauthorizenv -S session.ctx -C $nv_test_index -P nvpass $nv_test_index
tpm2_unseal -c key.ctx -p session:session.ctx
tpm2_flushcontext session.ctx

# Define another auth policy and write to the NV Index
tpm2_startauthsession -S session.ctx
tpm2_policypcr -S session.ctx -l sha1:23 -L policy.pcr0
tpm2_flushcontext session.ctx
echo "000b" | xxd -p -r | cat - policy.pcr0 | \
tpm2_nvwrite  -C $nv_test_index -P nvpass $nv_test_index -i-

# Satisfy the auth policy = policypassword not stored in the NV Index and
# then the policyauthorizenv and
# attempt user operation UNSEAL
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policypassword -S session.ctx
# should fail
trap - ERR
tpm2_policyauthorizenv -S session.ctx -C $nv_test_index -P nvpass $nv_test_index
if [ $? != 1 ];then
 echo "FAIL:tpm2_policyauthorizenv didn't fail!"
 exit 1
fi
trap onerror ERR
tpm2_flushcontext session.ctx

# Satisfy the auth policy stored in the NV Index and thus policyauthorizenv
# And attempt user operation UNSEAL
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policypcr -S session.ctx -l sha1:23 -L policy.pcr0
tpm2_policyauthorizenv -S session.ctx -C $nv_test_index -P nvpass $nv_test_index
tpm2_unseal -c key.ctx -p session:session.ctx
tpm2_flushcontext session.ctx

exit 0
