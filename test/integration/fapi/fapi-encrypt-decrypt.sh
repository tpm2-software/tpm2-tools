set -e
source helpers.sh

start_up

CRYPTO_PROFILE="RSA"
setup_fapi $CRYPTO_PROFILE

function cleanup {
    # In case the test is skipped no key is created and a
    # failure is expected here. Therefore, we need to pass a successful
    # execution in any case
    tss2 delete --path=/ && true
    shut_down
}

trap cleanup EXIT

PLAIN_TEXT=$TEMP_DIR/plaintext.file
KEY_PATH="HS/SRK/myRSACrypt"
ENCRYPTED_FILE=$TEMP_DIR/encrypted.file
DECRYPTED_FILE=$TEMP_DIR/decrypted.file
PCR_POLICY_DATA=$TEMP_DIR/pol_pcr16_0.json
POLICY_PCR=policy/pcr-policy
TYPES="noDa,decrypt"
EMPTY_FILE=$TEMP_DIR/empty.file
BIG_FILE=$TEMP_DIR/big_file.file
LOG_FILE=$TEMP_DIR/log.file
touch $LOG_FILE

echo -n "Secret Text!" > $PLAIN_TEXT

set -x

if [ "$CRYPTO_PROFILE" = "ECC" ]; then
echo ECC currently not supported for encryption. Skipping test.
exit 077
fi

tss2 provision

expect <<EOF
# Try interactive prompt with 2 different passwords
spawn tss2 createkey --path=$KEY_PATH --type=$TYPES
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
spawn tss2 createkey --authValue=abc --type="noDa, decrypt"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

tss2 import --path=$POLICY_PCR --importData=$PCR_POLICY_DATA

expect <<EOF
# Try interactive prompt with empty passwords
spawn tss2 createkey --path=$KEY_PATH --type=$TYPES
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

echo "tss2 encrypt with EMPTY_FILE" # Expected to succeed
tss2 encrypt --keyPath=$KEY_PATH --plainText=$EMPTY_FILE \
    --cipherText=$ENCRYPTED_FILE --force

echo "tss2 encrypt with BIG_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 encrypt --keyPath=$KEY_PATH --plainText=$BIG_FILE \
    --cipherText=$ENCRYPTED_FILE --force 2> $LOG_FILE"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    set file [open $LOG_FILE r]
    set log [read \$file]
    close $file
    send_user "[lindex \$log]\n"
    exit 1
}
EOF

if [[ "`cat $LOG_FILE`" == $SANITIZER_FILTER ]]; then
  echo "Error: AddressSanitizer triggered."
  cat $LOG_FILE
  exit 1
fi

tss2 encrypt --keyPath=$KEY_PATH --plainText=$PLAIN_TEXT \
    --cipherText=$ENCRYPTED_FILE --force

expect <<EOF
# Try with missing keypath
spawn tss2 encrypt --plainText=$PLAIN_TEXT --cipherText=$ENCRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing plaintext
spawn tss2 encrypt --keyPath=$KEY_PATH --cipherText=$ENCRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing ciphertext
spawn tss2 encrypt --keyPath=$KEY_PATH --plainText=$PLAIN_TEXT
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong plaintext file
spawn tss2 encrypt --keyPath=$KEY_PATH --plainText=abc \
    --cipherText=$ENCRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing ciphertext
spawn tss2 decrypt --keyPath=$KEY_PATH --plainText=$DECRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing plaintext
spawn tss2 decrypt --keyPath=$KEY_PATH --cipherText=$ENCRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing keyPath
spawn tss2 decrypt --cipherText=$ENCRYPTED_FILE --plainText=$DECRYPTED_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Command has not failed as expected\n"
    exit 1
}
EOF

tss2 decrypt --keyPath=$KEY_PATH --cipherText=$ENCRYPTED_FILE \
    --plainText=$DECRYPTED_FILE --force


if [ "`cat $DECRYPTED_FILE`" != "`cat $PLAIN_TEXT`" ]; then
  echo "Encryption/Decryption failed"
  exit 1
fi

echo "tss2 decrypt with EMPTY_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 decrypt --keyPath=$KEY_PATH --cipherText=$EMPTY_FILE \
    --plainText=$DECRYPTED_FILE --force 2> $LOG_FILE"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    set file [open $LOG_FILE r]
    set log [read \$file]
    close $file
    send_user "[lindex \$log]\n"
    exit 1
}
EOF

if [[ "`cat $LOG_FILE`" == $SANITIZER_FILTER ]]; then
  echo "Error: AddressSanitizer triggered."
  cat $LOG_FILE
  exit 1
fi

echo "tss2 decrypt with BIG_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 decrypt --keyPath=$KEY_PATH --cipherText=$BIG_FILE \
    --plainText=$DECRYPTED_FILE --force 2> $LOG_FILE"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    set file [open $LOG_FILE r]
    set log [read \$file]
    close $file
    send_user "[lindex \$log]\n"
    exit 1
}
EOF

if [[ "`cat $LOG_FILE`" == $SANITIZER_FILTER ]]; then
  echo "Error: AddressSanitizer triggered."
  cat $LOG_FILE
  exit 1
fi

tss2 delete --path=$KEY_PATH

# Encrypt/Decrypt with password
tss2 createkey --path=$KEY_PATH --type="noDa, decrypt" --authValue=abc
tss2 encrypt --keyPath=$KEY_PATH --plainText=$PLAIN_TEXT \
    --cipherText=$ENCRYPTED_FILE --force
echo -n "Fail" > $DECRYPTED_FILE
expect <<EOF
spawn tss2 decrypt --keyPath=$KEY_PATH --cipherText=$ENCRYPTED_FILE \
    --plainText=$DECRYPTED_FILE --force
expect "Authorize object : "
send "abc\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
    send_user "Authorization failed\n"
    exit 1
}
EOF

if [ "`cat $DECRYPTED_FILE`" != "`cat $PLAIN_TEXT`" ]; then
  echo "Encryption/Decryption failed"
  exit 1
fi

# Try tss2 createkey with missing type. This only works for tpm2-tss >=2.4.2.
# Therefore, make the test conditional
VERSION="$(tss2 createkey -v | grep -Po 'fapi-version=.*' | grep -Eo '([0-9]+\.{1})+[0-9]' | sed 's/[^0-9]*//g')"
if [ $VERSION -ge "242" ]; then
    tss2 delete --path=$KEY_PATH
    tss2 createkey --path=$KEY_PATH --authValue=abc
fi

exit 0
