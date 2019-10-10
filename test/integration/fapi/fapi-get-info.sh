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

DATA_OUTPUT_FILE=$TEMP_DIR/output.file

tss2_provision

tss2_getinfo --info $DATA_OUTPUT_FILE --force

if [ ! -s $DATA_OUTPUT_FILE ]
then
     echo "File is empty"
     exit 1
fi

expect <<EOF
# Try with missing info file
spawn tss2_getinfo --info $DATA_OUTPUT_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0