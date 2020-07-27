
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

KEY_PATH=HS/SRK/myRSACrypt
# DESCRIPTION_SET=$TEMP_DIR/set_description.file
DESCRIPTION_FILE=$TEMP_DIR/object_description.file
DESCRIPTION_SET="description data"

tss2 provision

tss2 createkey --path=$KEY_PATH --type="noDa, restricted, decrypt" \
    --authValue=""

tss2 setdescription --path=$KEY_PATH --description="$(echo $DESCRIPTION_SET)"

tss2 getdescription --path=$KEY_PATH --description=$DESCRIPTION_FILE --force

if [ "$(< $DESCRIPTION_FILE)" !=  "$DESCRIPTION_SET" ]; then
  echo "Descriptions not equal"
  exit 1
fi

expect <<EOF
# Try with missing path
spawn tss2 setdescription --description=$DESCRIPTION_SET
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

# Try with missing description, should set description to empty
tss2 setdescription --path=$KEY_PATH
tss2 getdescription --path=$KEY_PATH --description=$DESCRIPTION_FILE --force

if [ "$(< $DESCRIPTION_FILE)" !=  "" ]; then
  echo "Description is not empty"
  exit 1
fi

expect <<EOF
# Try with missing path
spawn tss2 getdescription --description=$DESCRIPTION_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing description
spawn tss2 getdescription --path=$KEY_PATH
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
