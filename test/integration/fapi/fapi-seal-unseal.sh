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

KEY_PATH=HS/SRK/sealKey
SEALED_DATA=$TEMP_DIR/seal-data.file
printf "data to seal" > $SEALED_DATA
UNSEALED_DATA_FILE=$TEMP_DIR/unsealed-data.file
PCR_POLICY_DATA=$TEMP_DIR/pol_pcr16_0.json
POLICY_PCR=policy/pcr-policy

tss2_provision

expect <<EOF
# Try interactive prompt with different passwords
spawn tss2_createseal --path $KEY_PATH --policyPath $POLICY_PCR --type "noDa" \
    --data $SEALED_DATA
expect "Authorize object Password: "
send "1\r"
expect "Authorize object Retype password: "
send "2\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Using interactive prompt with different passwords
    has not failed as expected.\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing path
spawn tss2_createseal --type "noDa" --data $SEALED_DATA --authValue ""
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing type
spawn tss2_createseal --path $KEY_PATH --data $SEALED_DATA --authValue ""
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tss2_import --path $POLICY_PCR --importData $PCR_POLICY_DATA

tss2_createseal --path $KEY_PATH --policyPath $POLICY_PCR --type "noDa" \
    --data $SEALED_DATA --authValue ""
tss2_unseal --path $KEY_PATH --data $UNSEALED_DATA_FILE --force

if [ "`cat $UNSEALED_DATA_FILE`" != "`cat $SEALED_DATA`" ]; then
  echo "Seal/Unseal failed"
  exit 1
fi

expect <<EOF
# Try with missing path
spawn tss2_unseal --data $UNSEALED_DATA_FILE --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing data
spawn tss2_unseal --path $KEY_PATH --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF



exit 0