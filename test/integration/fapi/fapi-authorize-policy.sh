
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

KEY_PATH=HS/SRK/mySignKey
POLICY_SIGN_KEY_PATH=HS/SRK/myPolicySignKey
PCR_POLICY_DATA=$TEMP_DIR/pol_pcr16_0.json
AUTHORIZE_POLICY_DATA=$TEMP_DIR/pol_authorize_ref.json
POLICY_PCR=policy/pcr-policy
POLICY_AUTHORIZE=policy/authorize-policy
POLICY_REF=$TEMP_DIR/policy_ref.file
SIGNATURE_FILE=$TEMP_DIR/signature.file
PUBLIC_KEY_FILE=$TEMP_DIR/public_key.file
DIGEST_FILE=$TEMP_DIR/digest.file
LOG_FILE=$TEMP_DIR/log.file

touch $LOG_FILE

EMPTY_FILE=$TEMP_DIR/empty.file
BIG_FILE=$TEMP_DIR/big_file.file

echo -n 01234567890123456789012345678901 > $DIGEST_FILE
echo 'f0f1f2f3f4f5f6f7f8f9' | xxd -r -p > $POLICY_REF

tss2 provision

tss2 import --path=$POLICY_PCR --importData=$PCR_POLICY_DATA

tss2 import --path=$POLICY_AUTHORIZE --importData=$AUTHORIZE_POLICY_DATA

echo "tss2 import with EMPTY_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 import --path=$POLICY_AUTHORIZE --importData=$EMPTY_FILE 2> $LOG_FILE"
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

echo "tss2 import with BIG_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 import --path=$POLICY_AUTHORIZE --importData=$BIG_FILE 2> $LOG_FILE"
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

tss2 createkey --path=$POLICY_SIGN_KEY_PATH --type="noDa, sign" --authValue=""

tss2 authorizepolicy --keyPath=$POLICY_SIGN_KEY_PATH --policyPath=$POLICY_PCR \
    --policyRef=$POLICY_REF

tss2 createkey --path=$KEY_PATH --type="noDa, sign" \
    --policyPath=$POLICY_AUTHORIZE --authValue=""

if [ "$CRYPTO_PROFILE" = "RSA" ]; then
    tss2 sign --keyPath=$KEY_PATH --padding="RSA_PSS" --digest=$DIGEST_FILE \
        --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
else
    tss2 sign --keyPath=$KEY_PATH --digest=$DIGEST_FILE \
        --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
fi

echo "tss2 sign with BIG_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 sign --keyPath=$KEY_PATH --padding=RSA_PSS --digest=$BIG_FILE \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE 2> $LOG_FILE"
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
# Try with missing policyPath
spawn tss2 authorizepolicy --keyPath=$POLICY_SIGN_KEY_PATH \
    --policyRef=$POLICY_REF
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing keyPath
spawn tss2 authorizepolicy \
    --policyPath=$POLICY_PCR --policyRef=$POLICY_REF
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

echo "tss2 authorizepolicy with EMPTY_FILE" # Expected to succeed
tss2 authorizepolicy --keyPath=$POLICY_SIGN_KEY_PATH --policyPath=$POLICY_PCR \
  --policyRef=$EMPTY_FILE

echo "tss2 authorizepolicy with BIG_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 authorizepolicy --keyPath=$POLICY_SIGN_KEY_PATH \
    --policyPath=$POLICY_PCR --policyRef=$BIG_FILE 2> $LOG_FILE"
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

exit 0
