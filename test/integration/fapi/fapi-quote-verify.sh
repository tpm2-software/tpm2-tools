
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

KEY_PATH=HS/SRK/quotekey
NONCE_FILE=$TEMP_DIR/nonce.file
PUBLIC_QUOTE_KEY=$TEMP_DIR/public_quote.key
QUOTE_INFO=$TEMP_DIR/quote.info
QUOTE_EMPTY_INFO=$TEMP_DIR/quote_empty.info
SIGNATURE_FILE=$TEMP_DIR/signature.file
CERTIFICATE_FILE=$TEMP_DIR/certificate.file
PCR_LOG=$TEMP_DIR/pcr.log

printf "01234567890123456789" > $NONCE_FILE
printf "01234567890123456789" > $PCR_LOG

EMPTY_FILE=$TEMP_DIR/empty.file
BIG_FILE=$TEMP_DIR/big_file.file

LOG_FILE=$TEMP_DIR/log.file
touch $LOG_FILE

tss2 provision

tss2 createkey --path=$KEY_PATH --type="noDa, restricted, sign" --authValue=""

tss2 exportkey --pathOfKeyToDuplicate=$KEY_PATH --exportedData=$PUBLIC_QUOTE_KEY --force
tss2 import --path="ext/myNewParent" --importData=$PUBLIC_QUOTE_KEY


tss2 quote --keyPath=$KEY_PATH --pcrList="11, 12, 13, 14, 15, 16" --qualifyingData=$NONCE_FILE \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG \
    --certificate=$CERTIFICATE_FILE --quoteInfo=$QUOTE_INFO --force

tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=$NONCE_FILE --quoteInfo=$QUOTE_INFO \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG

echo "tss2 quote with EMPTY_FILE" # Expected to succeed
tss2 quote --keyPath=$KEY_PATH --pcrList="11, 12, 13, 14, 15, 16" \
    --qualifyingData=$EMPTY_FILE --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG \
    --certificate=$CERTIFICATE_FILE --quoteInfo=$QUOTE_EMPTY_INFO --force

echo "tss2 verifyquote with EMPTY_FILE qualifyingData" # Expected to succeed
tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=$EMPTY_FILE --quoteInfo=$QUOTE_EMPTY_INFO \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG

# Try with missing qualifyingData
tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --quoteInfo=$QUOTE_EMPTY_INFO \
    --signature=$SIGNATURE_FILE

echo "tss2 quote with BIG_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 quote --keyPath=$KEY_PATH --pcrList=\"11, 12, 13, 14, 15, 16\" \
    --qualifyingData=$BIG_FILE --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG \
    --certificate=$CERTIFICATE_FILE --quoteInfo=$QUOTE_INFO --force 2> $LOG_FILE"
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

echo "tss2 verifyquote with BIG_FILE qualifyingData" # Expected to fail
expect <<EOF
spawn sh -c "tss2 verifyquote --publicKeyPath=\"ext/myNewParent\" \
    --qualifyingData=$BIG_FILE --quoteInfo=$QUOTE_INFO \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG 2> $LOG_FILE"
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

echo "tss2 verifyquote with EMPTY_FILE signature" # Expected to fail
expect <<EOF
spawn sh -c "tss2 verifyquote --publicKeyPath=\"ext/myNewParent\" \
    --qualifyingData=$NONCE_FILE --quoteInfo=$QUOTE_INFO \
    --signature=$EMPTY_FILE --pcrLog=$PCR_LOG 2> $LOG_FILE"
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

echo "tss2 verifyquote with BIG_FILE signature" # Expected to fail
expect <<EOF
spawn sh -c "tss2 verifyquote --publicKeyPath=\"ext/myNewParent\" \
    --qualifyingData=$NONCE_FILE --quoteInfo=$QUOTE_INFO \
    --signature=$BIG_FILE --pcrLog=$PCR_LOG 2> $LOG_FILE"
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

echo "tss2 verifyquote with EMPTY_FILE quoteInfo" # Expected to fail
expect <<EOF
spawn sh -c "tss2 verifyquote --publicKeyPath=\"ext/myNewParent\" \
    --qualifyingData=$NONCE_FILE --quoteInfo=$EMPTY_FILE \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG 2> $LOG_FILE"
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

echo "tss2 verifyquote with BIG_FILE quoteInfo" # Expected to fail
expect <<EOF
spawn sh -c "tss2 verifyquote --publicKeyPath=\"ext/myNewParent\" \
    --qualifyingData=$NONCE_FILE --quoteInfo=$BIG_FILE \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG 2> $LOG_FILE"
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

echo "tss2 verifyquote with EMPTY_FILE pcrLog" # Expected to fail
expect <<EOF
spawn sh -c "tss2 verifyquote --publicKeyPath=\"ext/myNewParent\" \
    --qualifyingData=$NONCE_FILE --quoteInfo=$QUOTE_INFO \
    --signature=$SIGNATURE_FILE --pcrLog=$EMPTY_FILE 2> $LOG_FILE"
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

echo "tss2 verifyquote with BIG_FILE pcrLog" # Expected to fail
expect <<EOF
spawn sh -c "tss2 verifyquote --publicKeyPath=\"ext/myNewParent\" \
    --qualifyingData=$NONCE_FILE --quoteInfo=$QUOTE_INFO \
    --signature=$SIGNATURE_FILE --pcrLog=$BIG_FILE 2> $LOG_FILE"
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

expect <<EOF
# Try with missing keyPath
spawn tss2 quote --pcrList="16" \
    --qualifyingData=$NONCE_FILE --signature=$SIGNATURE_FILE \
    --pcrLog=$PCR_LOG --certificate=$CERTIFICATE_FILE \
    --quoteInfo=$QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing pcrList
spawn tss2 quote \
    --qualifyingData=$NONCE_FILE --signature=$SIGNATURE_FILE \
    --pcrLog=$PCR_LOG --certificate=$CERTIFICATE_FILE \
    --quoteInfo=$QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing signature
spawn tss2 quote --keyPath=$KEY_PATH --pcrList="16" \
    --qualifyingData=$NONCE_FILE \
    --pcrLog=$PCR_LOG --certificate=$CERTIFICATE_FILE \
    --quoteInfo=$QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing quoteInfo
spawn tss2 quote --keyPath=$KEY_PATH --pcrList="16" \
    --qualifyingData=$NONCE_FILE --signature=$SIGNATURE_FILE \
    --pcrLog=$PCR_LOG --certificate=$CERTIFICATE_FILE \
    --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (1)
spawn tss2 quote --keyPath=$KEY_PATH --pcrList="16" \
    --qualifyingData=$NONCE_FILE --signature=- \
    --pcrLog=- --certificate=$CERTIFICATE_FILE \
    --quoteInfo=$QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (2)
spawn tss2 quote --keyPath=$KEY_PATH --pcrList="16" \
    --qualifyingData=$NONCE_FILE --signature=$SIGNATURE_FILE \
    --pcrLog=- --certificate=- \
    --quoteInfo=$QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (3)
spawn tss2 quote --keyPath=$KEY_PATH --pcrList="16" \
    --qualifyingData=$NONCE_FILE --signature=$SIGNATURE_FILE \
    --pcrLog=$PCR_LOG --certificate=- \
    --quoteInfo=- --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (4)
spawn tss2 quote --keyPath=$KEY_PATH --pcrList "16" \
    --qualifyingData=- --signature $SIGNATURE_FILE \
    --pcrLog=- --certificate=$CERTIFICATE_FILE \
    --quoteInfo=- --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong pcrs
spawn tss2 quote --keyPath=$KEY_PATH --pcrList=abc --qualifyingData=$NONCE_FILE \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG \
    --certificate=$CERTIFICATE_FILE --quoteInfo=$QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Fail quote
spawn tss2 quote --keyPath="/abc/def" --pcrList="16" --qualifyingData=$NONCE_FILE \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG \
    --certificate=$CERTIFICATE_FILE --quoteInfo=$QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with already existing directory
spawn tss2 quote --keyPath=$KEY_PATH --pcrList="16" --qualifyingData=$NONCE_FILE \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG \
    --certificate=$CERTIFICATE_FILE --quoteInfo=$QUOTE_INFO
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

# Try with missing qualifyingData
tss2 quote --keyPath=$KEY_PATH --pcrList="16" \
    --signature=$SIGNATURE_FILE \
    --pcrLog=$PCR_LOG --certificate=$CERTIFICATE_FILE \
    --quoteInfo=$QUOTE_INFO --force

# Try with missing pcrLog
tss2 quote --keyPath=$KEY_PATH --pcrList="16" \
    --qualifyingData=$NONCE_FILE --signature=$SIGNATURE_FILE \
    --certificate=$CERTIFICATE_FILE \
    --quoteInfo=$QUOTE_INFO --force

# Try with missing certificate
tss2 quote --keyPath=$KEY_PATH --pcrList="16" \
    --qualifyingData=$NONCE_FILE --signature=$SIGNATURE_FILE \
    --pcrLog=$PCR_LOG \
    --quoteInfo=$QUOTE_INFO --force

expect <<EOF
# Try with missing publicKeyPath
spawn tss2 verifyquote \
    --qualifyingData=$NONCE_FILE --quoteInfo=$QUOTE_INFO \
    --signature=$SIGNATURE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing quoteInfo
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=$NONCE_FILE \
    --signature=$SIGNATURE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing signature
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=$NONCE_FILE --quoteInfo=$QUOTE_INFO
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (1)
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=- --quoteInfo=- \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (2)
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=$NONCE_FILE --quoteInfo=- \
    --signature=- --pcrLog=$PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (3)
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=$NONCE_FILE --quoteInfo=$QUOTE_INFO \
    --signature=- --pcrLog=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (4)
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=- --quoteInfo=$QUOTE_INFO \
    --signature=$SIGNATURE_FILE --pcrLog=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (5)
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=$NONCE_FILE --quoteInfo=- \
    --signature=- --pcrLog=$PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (6)
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=- --quoteInfo=- \
    --signature=- --pcrLog=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong qualifyingData file
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=abc --quoteInfo=$QUOTE_INFO \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong signature file
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=$NONCE_FILE --quoteInfo=$QUOTE_INFO \
    --signature=abc --pcrLog=$PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong quoteInfo file
spawn tss2 verifyquote --publicKeyPath="ext/myNewParent" \
    --qualifyingData=$NONCE_FILE --quoteInfo=abc \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try failing tss2 verifyquote
spawn tss2 verifyquote --publicKeyPath="ext/abc" \
    --qualifyingData=$NONCE_FILE --quoteInfo=abc \
    --signature=$SIGNATURE_FILE --pcrLog=$PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
