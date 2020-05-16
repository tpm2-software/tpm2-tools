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

NV_PATH=/nv/Owner/NvExtend
DATA_EXTEND_FILE=$TEMP_DIR/nv_extend.data
DATA_READ_FILE=$TEMP_DIR/nv_read.data
LOG_DATA=$TEMP_DIR/log.data
READ_LOG_DATA=$TEMP_DIR/read_log.data

echo -n 01234567890123456789 > $DATA_EXTEND_FILE
echo -n 01234567890123456789 > $LOG_DATA

tss2_provision

tss2_createnv --path $NV_PATH --type "noDa, pcr" --size 0 --authValue ""

tss2_nvextend --nvPath $NV_PATH --data $DATA_EXTEND_FILE --logData $LOG_DATA

tss2_nvread --nvPath $NV_PATH --data $DATA_READ_FILE --logData $READ_LOG_DATA

if [ ! -f $READ_LOG_DATA ]; then
    echo "No log data returned"
    exit 1
fi

expect <<EOF
# Try with missing nvPath
spawn tss2_nvextend --data $DATA_EXTEND_FILE --logData $LOG_DATA
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing data
spawn tss2_nvextend --nvPath $NV_PATH --logData $LOG_DATA
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdin
spawn tss2_nvextend --nvPath $NV_PATH --data - --logData -
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0