
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

KEY_PATH="HS/SRK/myRSADecrypt"
KEY_PATH_PARENT="HS/SRK/myParent"
JSON_POLICY=$TEMP_DIR/pol_duplicate.json
DUPLICATE_POLICY=policy/duplicate-policy
EXPORTED_KEY=$TEMP_DIR/exportedKey
EXPORTED_PARENT_KEY=$TEMP_DIR/exportedParentKey
LOADED_KEY="myNewParent"

tss2 provision

tss2 import --path=$DUPLICATE_POLICY --importData=$JSON_POLICY

expect <<EOF
# Try with missing path
spawn tss2 import --importData=$JSON_POLICY
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing importData
spawn tss2 import --path=$DUPLICATE_POLICY
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tss2 createkey --path=$KEY_PATH_PARENT --type="restricted, decrypt, noDA" \
    --authValue=""

tss2 exportkey --pathOfKeyToDuplicate=$KEY_PATH_PARENT \
    --exportedData=$EXPORTED_PARENT_KEY --force

tss2 import --path="ext/$LOADED_KEY" --importData=$EXPORTED_PARENT_KEY

tss2 createkey --path=$KEY_PATH --type="noDa, exportable, decrypt" \
    --policyPath=$DUPLICATE_POLICY --authValue=""

tss2 exportkey --pathOfKeyToDuplicate=$KEY_PATH \
    --pathToPublicKeyOfNewParent="ext/$LOADED_KEY" --exportedData=$EXPORTED_KEY

expect <<EOF
# Try with missing exportedData
spawn tss2 exportkey --pathOfKeyToDuplicate=$KEY_PATH \
    --pathToPublicKeyOfNewParent="ext/$LOADED_KEY"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing pathOfKeyToDuplicate
spawn tss2 exportkey --pathToPublicKeyOfNewParent="ext/$LOADED_KEY" \
    --exportedData=$EXPORTED_KEY
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try to fail command
spawn tss2 exportkey --pathOfKeyToDuplicate=$KEY_PATH \
    --pathToPublicKeyOfNewParent="ext/$LOADED_KEY" --exportedData=
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try to fail writing to output
spawn tss2 exportkey --pathOfKeyToDuplicate=$KEY_PATH \
    --pathToPublicKeyOfNewParent="ext/$LOADED_KEY" --exportedData=$EXPORTED_KEY
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
