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

PW=abc
NV_PATH=/nv/Owner/myNVwrite
DATA_WRITE_FILE=$TEMP_DIR/nv_write_data.file
DATA_READ_FILE=$TEMP_DIR/nv_read_data.file

tss2_provision

echo 1234567890123456789 > $DATA_WRITE_FILE

tss2_createnv --path $NV_PATH --type "noDa" --size 20 --authValue ""

tss2_nvwrite --nvPath $NV_PATH --data $DATA_WRITE_FILE

tss2_nvread --nvPath $NV_PATH --data $DATA_READ_FILE --force

if [ `cat $DATA_READ_FILE` !=  `cat $DATA_WRITE_FILE` ]; then
  echo "Test without password: Strings are not equal"
  exit 99
fi

tss2_delete --path $NV_PATH

tss2_createnv --path $NV_PATH --type "noDa" --size 20 --authValue=$PW

expect <<EOF
# Check if system asks for auth value and provide it
spawn tss2_nvwrite --nvPath $NV_PATH --data $DATA_WRITE_FILE
expect {
    "Authorize object: " {
    } eof {
        send_user "The system has not asked for password\n"
        exit 1
    }
    }
    send "$PW\r"
    set ret [wait]
    if {[lindex \$ret 2] || [lindex \$ret 3]} {
        send_user "Passing password has failed\n"
        exit 1
    }
EOF

expect <<EOF
# Try with missing nvPath
spawn tss2_nvread --data $DATA_READ_FILE --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing data
spawn tss2_nvread --nvPath $NV_PATH  --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (1)
spawn tss2_nvread --nvPath $NV_PATH --data - --logData - --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing nvPath
spawn tss2_nvwrite --data $DATA_WRITE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing data
spawn tss2_nvwrite --data $DATA_WRITE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tss2_delete --path $NV_PATH

expect <<EOF
# Try interactive prompt
spawn tss2_createnv --path $NV_PATH --type "noDa" --size 20
expect "Authorize object Password: "
send "$PW\r"
expect "Authorize object Retype password: "
send "$PW\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
    send_user "Using interactive prompt with password has failed\n"
    exit 1
}
EOF

exit 0