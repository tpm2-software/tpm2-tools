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

KEY_PATH=HS/SRK/myRSACrypt
DESCRIPTION_SET=$TEMP_DIR/object-description
DESCRIPTION_FILE=$TEMP_DIR/object_description.file

echo -n "description data" > DESCRIPTION_SET

tss2_provision

tss2_createkey --path $KEY_PATH --type "noDa, restricted, decrypt" \
    --authValue ""

tss2_setdescription --path $KEY_PATH --description $DESCRIPTION_SET

tss2_getdescription --path $KEY_PATH --description $DESCRIPTION_FILE --force

if [ `cat $DESCRIPTION_FILE` !=  "$DESCRIPTION_SET" ]; then
  echo "Descriptions not equal"
  exit 1
fi

expect <<EOF
# Try with missing path
spawn tss2_setdescription --description $DESCRIPTION_SET
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing path
spawn tss2_getdescription --description $DESCRIPTION_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing description
spawn tss2_getdescription --path $KEY_PATH
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0