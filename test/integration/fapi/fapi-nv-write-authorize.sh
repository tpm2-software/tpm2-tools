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

POLICY_SIGN_KEY_PATH="HS/SRK/policySignKey"
SIGN_KEY_PATH="HS/SRK/signKey"
NV_PATH="/nv/Owner/myNV"
PCR_POLICY_JSON=$TEMP_DIR/pol_pcr16_0.json
POLICY_PCR=policy/pcr-policy
AUTHORIZE_NV_POLICY_JSON=$TEMP_DIR/pol_authorize_nv.json
AUTHORIZE_NV_POLICY=policy/authorize-nv-policy
SIGNATURE_FILE=$TEMP_DIR/signature.file
PUBLIC_KEY_FILE=$TEMP_DIR/public_key.file
DIGEST_FILE=$TEMP_DIR/digest.file
echo -n 01234567890123456789 > $DIGEST_FILE

tss2_provision

tss2_createnv --path $NV_PATH --type "noDa" --size 34 --authValue ""

tss2_import --path $AUTHORIZE_NV_POLICY --importData $AUTHORIZE_NV_POLICY_JSON

tss2_import --path $POLICY_PCR --importData $PCR_POLICY_JSON

expect <<EOF
# Try if command is supported
spawn tss2_writeauthorizenv --nvPath $NV_PATH --policyPath $POLICY_PCR
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
    send_user "Command has failed. If using a physical TPM, see log since it is
    probably not supported by TPM. Skipping test\n"
    exit 77
}
EOF

tss2_createkey --path $POLICY_SIGN_KEY_PATH --type "noDa, sign" --authValue ""

tss2_createkey --path $SIGN_KEY_PATH --type "noDa, sign" \
    --policyPath $AUTHORIZE_NV_POLICY  --authValue ""

tss2_sign --keyPath $SIGN_KEY_PATH --padding "RSA_PSS" --digest $DIGEST_FILE \
    --signature $SIGNATURE_FILE --publicKey $PUBLIC_KEY_FILE

expect <<EOF
# Try with missing nvPath
spawn tss2_writeauthorizenv --policyPath $POLICY_PCR
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing policyPath
spawn tss2_writeauthorizenv --nvPath $NV_PATH
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try to fail command
spawn tss2_writeauthorizenv --nvPath /abc/def --policyPath $POLICY_PCR
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
