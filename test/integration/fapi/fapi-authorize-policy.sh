#!/bin/bash

set -e
source helpers.sh

start_up

setup_fapi

function cleanup {
    tss2_delete --path /
    shut_down
}

trap cleanup EXIT

KEY_PATH=HS/SRK/mySignKey
POLICY_SIGN_KEY_PATH=HS/SRK/myPolicySignKey
PCR_POLICY_DATA=$TEMP_DIR/pol_pcr16_0.json
AUTHORIZE_POLICY_DATA=$TEMP_DIR/pol_authorize_ref.json
POLICY_PCR=policy/pcr-policy
POLICY_AUTHORIZE=policy/authorize-policy
POLICY_REF=$TEMP_DIR/policy_ref.file
SIGNATURE_FILE=$TEMP_DIR/signature.file
PUBLIC_KEY_FILE=$TEMP_DIR/public_key.file
DIGEST_FILE=$TEMP_DIR/digest.file

echo -n 01234567890123456789012345678901 > $DIGEST_FILE
echo 'f0f1f2f3f4f5f6f7f8f9' | xxd -r -p > $POLICY_REF

tss2_provision

tss2_import --path $POLICY_PCR --importData $PCR_POLICY_DATA

tss2_import --path $POLICY_AUTHORIZE --importData $AUTHORIZE_POLICY_DATA

tss2_createkey --path $POLICY_SIGN_KEY_PATH --type "noDa, sign" --authValue ""

tss2_authorizepolicy --keyPath $POLICY_SIGN_KEY_PATH --policyPath $POLICY_PCR \
    --policyRef $POLICY_REF

tss2_createkey --path $KEY_PATH --type "noDa, sign" \
    --policyPath $POLICY_AUTHORIZE --authValue ""

tss2_sign --keyPath $KEY_PATH --padding "RSA_PSS" --digest $DIGEST_FILE \
    --signature $SIGNATURE_FILE --publicKey $PUBLIC_KEY_FILE


expect <<EOF
# Try with missing policyPath
spawn tss2_authorizepolicy --keyPath $POLICY_SIGN_KEY_PATH \
    --policyRef $POLICY_REF
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing keyPath
spawn tss2_authorizepolicy \
    --policyPath $POLICY_PCR --policyRef $POLICY_REF
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0