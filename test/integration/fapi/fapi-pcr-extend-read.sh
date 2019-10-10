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

NV_PATH=/nv/Owner/myNVwrite
PCR_DIGEST_FILE=$TEMP_DIR/pcr_digest.file
PCR_LOG_FILE_WRITE=$TEMP_DIR/pcr_log_write.file
echo "{\"test\": \"myfile\"}" > $PCR_LOG_FILE_WRITE
PCR_LOG_FILE_READ=$TEMP_DIR/pcr_log_read.file
PCR_EVENT_DATA=$TEMP_DIR/pcr_event_data.file
echo "0,1,2,3,4,5,6,7,8,9" > $PCR_EVENT_DATA

tss2_provision

tss2_pcrextend --pcr 16 --data $PCR_EVENT_DATA \
    --logData $PCR_LOG_FILE_WRITE

tss2_pcrread --pcrIndex 16 --pcrValue $PCR_DIGEST_FILE \
    --pcrLog $PCR_LOG_FILE_READ --force

if [ ! -s $PCR_DIGEST_FILE ] || [ ! -s $PCR_LOG_FILE_READ ]; then
    echo "At least one returned file is empty"
    exit 1
fi

expect <<EOF
# Try with missing pcr
spawn tss2_pcrextend --data $PCR_EVENT_DATA --logData $PCR_LOG_FILE_WRITE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing data
spawn tss2_pcrextend --pcr 16 --logData $PCR_LOG_FILE_WRITE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing logData
spawn tss2_pcrextend --pcr 16 --data $PCR_EVENT_DATA
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong pcr
spawn tss2_pcrextend --pcr abc --data $PCR_EVENT_DATA \
    --logData $PCR_LOG_FILE_WRITE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing pcrIndex
spawn tss2_pcrread --pcrValue $PCR_DIGEST_FILE --pcrLog $PCR_LOG_FILE_READ
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing pcrValue
spawn tss2_pcrread --pcrIndex 16 --pcrLog $PCR_LOG_FILE_READ
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing pcrLog
spawn tss2_pcrread --pcrIndex 16 --pcrValue $PCR_DIGEST_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with mutliple stdins
spawn tss2_pcrread --pcrIndex 16 --pcrValue=- \
    --pcrLog=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong pcrIndex
spawn tss2_pcrread --pcrIndex abc --pcrValue $PCR_DIGEST_FILE \
    --pcrLog $PCR_LOG_FILE_READ
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0