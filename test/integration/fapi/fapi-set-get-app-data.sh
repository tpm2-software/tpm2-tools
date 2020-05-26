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
APP_DATA_SET=$TEMP_DIR/sample_app_data
APP_DATA_FILE=$TEMP_DIR/app_data.file

echo -n "abcdef" > $APP_DATA_SET

tss2_provision

tss2_createkey --path $KEY_PATH --type "noDa, restricted, decrypt" \
    --authValue ""

tss2_setappdata --path $KEY_PATH --appData $APP_DATA_SET

tss2_getappdata --path $KEY_PATH --appData $APP_DATA_FILE --force

if [ "$(< $APP_DATA_FILE)" !=  "$(< $APP_DATA_SET)" ]; then
  echo "Files are not equal"
  exit 99
fi

echo -n "" > $APP_DATA_FILE
tss2_setappdata --path $KEY_PATH
tss2_getappdata --path $KEY_PATH --appData $APP_DATA_FILE --force

if [ "$(< $APP_DATA_FILE)" !=  "" ]; then
  echo "File not empty"
  exit 99
fi

echo -n "123" | tss2_setappdata --path $KEY_PATH --appData -
tss2_getappdata --path $KEY_PATH --appData $APP_DATA_FILE --force

if [ "$(< $APP_DATA_FILE)" !=  "123" ]; then
  echo "Files are not equal"
  exit 99
fi

expect <<EOF
# Try with missing path
spawn tss2_getappdata --appData $APP_DATA_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0