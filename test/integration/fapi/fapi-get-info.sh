
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

DATA_OUTPUT_FILE=$TEMP_DIR/output.file

tss2 provision

tss2 getinfo --info=$DATA_OUTPUT_FILE --force

if [ ! -s $DATA_OUTPUT_FILE ]
then
     echo "File is empty"
     exit 1
fi

expect <<EOF
# Try with missing info file
spawn tss2 getinfo
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
