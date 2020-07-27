
set -e
source helpers.sh

start_up

CRYPTO_PROFILE="RSA"
setup_fapi $CRYPTO_PROFILE

function cleanup {
    # If this test is successful, no keys are created. Thus, command below will
    # always fail
    tss2 delete --path=/ || true
    shut_down
}

trap cleanup EXIT

PW=abc
PLAIN_TEXT=$TEMP_DIR/plaintext.file
KEY_PATH="HS/SRK/myRSACrypt"
ENCRYPTED_FILE=$TEMP_DIR/encrypted.file
VERSION_FILE=$TEMP_DIR/version.file
echo -n "Secret Text!" > $PLAIN_TEXT

expect <<EOF
# Try with wrong help argument
spawn tss2 provision -h abc
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tss2 provision -h man

tss2 provision -h no-man

tss2 provision -v

expect <<EOF
# Try with wrong option
spawn tss2 provision -abcdef
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tss2 getrandom -v > $VERSION_FILE
VERSION=$(cat $VERSION_FILE | cut -d'=' -f 4)
size=${#VERSION}
if [ $size -ge 129 ]; then
    echo "Error: Version length greater than 128 characters" ; exit 1
fi

exit 0
