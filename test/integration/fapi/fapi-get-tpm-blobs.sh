
set -e
source helpers.sh

start_up

CRYPTO_PROFILE="RSA"
setup_fapi $CRYPTO_PROFILE

function cleanup {
    tss2 delete --path=/
    shut_down
}

trap cleanup EXIT

KEY_PATH="HS/SRK/myRSASign"
PUBLIC_KEY_FILE=$TEMP_DIR/pub_key.file
PRIVATE_KEY_FILE=$TEMP_DIR/priv_key.file
POLICY_FILE=$TEMP_DIR/policy.file
PCR_POLICY_DATA=$TEMP_DIR/pol_pcr16_0.json
POLICY_PCR=policy/pcr-policy

tss2 provision

tss2 import --path=$POLICY_PCR --importData=$PCR_POLICY_DATA

tss2 createkey --path=$KEY_PATH --policyPath=$POLICY_PCR --type="noDa, sign" \
    --authValue=""

tss2 gettpmblobs --path=$KEY_PATH --tpm2bPublic=$PUBLIC_KEY_FILE \
    --tpm2bPrivate=$PRIVATE_KEY_FILE --policy=$POLICY_FILE --force

expect <<EOF
# Try with missing path
spawn tss2 gettpmblobs --tpm2bPublic=$PUBLIC_KEY_FILE \
    --tpm2bPrivate=$PRIVATE_KEY_FILE --policy=$POLICY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing tpm2bPublic
spawn tss2 gettpmblobs --path=$KEY_PATH \
    --tpm2bPrivate=$PRIVATE_KEY_FILE --policy=$POLICY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing tpm2bPrivate
spawn tss2 gettpmblobs --path=$KEY_PATH --tpm2bPublic=$PUBLIC_KEY_FILE \
    --policy=$POLICY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing policy
spawn tss2 gettpmblobs --path=$KEY_PATH --tpm2bPublic=$PUBLIC_KEY_FILE \
    --tpm2bPrivate=$PRIVATE_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with existing directory PUBLIC_KEY_FILE
spawn tss2 gettpmblobs --path=$KEY_PATH --tpm2bPublic=$PUBLIC_KEY_FILE \
    --tpm2bPrivate=$PRIVATE_KEY_FILE --policy=$POLICY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (1)
spawn tss2 gettpmblobs --path=$KEY_PATH --tpm2bPublic=- \
    --tpm2bPrivate=- --policy=$POLICY_FILE --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (2)
spawn tss2 gettpmblobs --path=$KEY_PATH --tpm2bPublic=$PUBLIC_KEY_FILE \
    --tpm2bPrivate=- --policy=- --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (3)
spawn tss2 gettpmblobs --path=$KEY_PATH --tpm2bPublic=- \
    --tpm2bPrivate=$PRIVATE_KEY_FILE --policy=- --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (4)
spawn tss2 gettpmblobs --path=$KEY_PATH --tpm2bPublic=- \
    --tpm2bPrivate=- --policy=- --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
