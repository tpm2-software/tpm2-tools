#!/bin/bash

set -e
source helpers.sh

start_up

setup_fapi

PATH=${BUILDDIR}/tools/fapi:$PATH

function cleanup {
    tss2_delete --path /
    shut_down
}

trap cleanup EXIT

OUTPUT_FILE="$TEMP_DIR/output.file"

tss2_provision

expect <<EOF
# Try with wrong size value
spawn tss2_getrandom --numBytes a --data $OUTPUT_FILE --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing output
spawn tss2_getrandom --numBytes 20
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing numBytes
spawn tss2_getrandom --data $OUTPUT_FILE --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tss2_getrandom --numBytes 4 --data $OUTPUT_FILE --force


exit 0
