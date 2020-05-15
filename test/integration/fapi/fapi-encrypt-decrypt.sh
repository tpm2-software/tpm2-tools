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

PLAIN_TEXT=$TEMP_DIR/plaintext.file
KEY_PATH="HS/SRK/myRSACrypt"
ENCRYPTED_FILE=$TEMP_DIR/encrypted.file
DECRYPTED_FILE=$TEMP_DIR/decrypted.file
PCR_POLICY_DATA=$TEMP_DIR/pol_pcr16_0.json
POLICY_PCR=policy/pcr-policy

echo -n "Secret Text!" > $PLAIN_TEXT

set -x

tss2_provision

expect <<EOF
# Try interactive prompt with 2 different passwords
spawn tss2_createkey --path $KEY_PATH --type "noDa, decrypt"
expect "Authorize object Password: "
send "1\r"
expect "Authorize object Retype password: "
send "2\r"
expect {
    "Passwords do not match." {
            } eof {
                send_user "Expected password mismatch, but got nothing, or
                rather EOF\n"
                exit 1
            }
        }
        set ret [wait]
        if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
            send_user "Using interactive prompt with different passwords
            has not failed\n"
            exit 1
        }
EOF

expect <<EOF
# Try with missing path
spawn tss2_createkey --authValue abc --type "noDa, decrypt"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

tss2_import --path $POLICY_PCR --importData $PCR_POLICY_DATA

expect <<EOF
# Try interactive prompt with empty passwords
spawn tss2_createkey --path $KEY_PATH --type "noDa, decrypt"
expect "Authorize object Password: "
send "\r"
expect "Authorize object Retype password: "
send "\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
    send_user "Using interactive prompt with null password
    has failed\n"
    exit 1
}
EOF

tss2_encrypt --keyPath $KEY_PATH --plainText $PLAIN_TEXT \
    --cipherText $ENCRYPTED_FILE --force

expect <<EOF
# Try with missing keypath
spawn tss2_encrypt --plainText $PLAIN_TEXT --cipherText $ENCRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing plaintext
spawn tss2_encrypt --keyPath $KEY_PATH --cipherText $ENCRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing ciphertext
spawn tss2_encrypt --keyPath $KEY_PATH --plainText $PLAIN_TEXT
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong plaintext file
spawn tss2_encrypt --keyPath $KEY_PATH --plainText abc \
    --cipherText $ENCRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing ciphertext
spawn tss2_decrypt --keyPath $KEY_PATH --plainText $DECRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing plaintext
spawn tss2_decrypt --keyPath $KEY_PATH --cipherText $ENCRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing keyPath
spawn tss2_decrypt --cipherText $ENCRYPTED_FILE --plainText $DECRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

tss2_decrypt --keyPath $KEY_PATH --cipherText $ENCRYPTED_FILE \
    --plainText $DECRYPTED_FILE --force


if [ "`cat $DECRYPTED_FILE`" != "`cat $PLAIN_TEXT`" ]; then
  echo "Encryption/Decryption failed"
  exit 1
fi

exit 0
