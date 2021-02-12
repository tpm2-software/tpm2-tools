
set -e
source helpers.sh

start_up

CRYPTO_PROFILE="RSA"
setup_fapi $CRYPTO_PROFILE

PATH=${abs_builddir}/tools/fapi:$PATH

function cleanup {
    tss2 delete --path=/
    shut_down
}

trap cleanup EXIT

OUTPUT_FILE="$TEMP_DIR/output.file"

tss2 provision

expect <<EOF
# Try with wrong size value
spawn tss2 getrandom --numBytes=a --data=$OUTPUT_FILE --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing output
spawn tss2 getrandom --numBytes=20
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing numBytes
spawn tss2 getrandom --data=$OUTPUT_FILE --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tss2 getrandom --numBytes=4 --data=$OUTPUT_FILE --force

tss2 getrandom --numBytes=4 --hex --data=$OUTPUT_FILE --force

exit 0
