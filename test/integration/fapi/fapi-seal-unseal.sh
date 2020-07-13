
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

KEY_PATH=HS/SRK/sealKey
SEALED_DATA_FILE=$TEMP_DIR/seal-data.file
SEAL_DATA="data to seal"
printf "$SEAL_DATA" > $SEALED_DATA_FILE
UNSEALED_DATA_FILE=$TEMP_DIR/unsealed-data.file
PCR_POLICY_DATA=$TEMP_DIR/pol_pcr16_0.json
POLICY_PCR=policy/pcr-policy
COUNT_FILE=$TEMP_DIR/count.file

EMPTY_FILE=$TEMP_DIR/empty.file
BIG_FILE=$TEMP_DIR/big_file.file

LOG_FILE=$TEMP_DIR/log.file
touch $LOG_FILE

tss2 provision

expect <<EOF
# Try interactive prompt with different passwords
spawn tss2 createseal --path=$KEY_PATH --policyPath=$POLICY_PCR --type="noDa" \
    --data=$SEALED_DATA_FILE
expect "Authorize object Password: "
send "1\r"
expect "Authorize object Retype password: "
send "2\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Using interactive prompt with different passwords
    has not failed as expected.\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing path
spawn tss2 createseal --type="noDa" --data=$SEALED_DATA_FILE --authValue=""
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tss2 import --path=$POLICY_PCR --importData=$PCR_POLICY_DATA

echo "tss2 createseal with EMPTY_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 createseal --path=$KEY_PATH --policyPath=$POLICY_PCR \
    --type=\"noDa\" --data=$EMPTY_FILE --authValue=\"\" 2> $LOG_FILE"
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

echo "tss2 createseal with BIG_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 createseal --path=$KEY_PATH --policyPath=$POLICY_PCR \
    --type=\"noDa\" --data=$BIG_FILE --authValue=\"\" 2> $LOG_FILE"
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

tss2 createseal --path=$KEY_PATH --policyPath=$POLICY_PCR --type="noDa" \
    --data=$SEALED_DATA_FILE --authValue=""
tss2 unseal --path=$KEY_PATH --data=$UNSEALED_DATA_FILE --force

if [ "`xxd $UNSEALED_DATA_FILE`" != "`xxd $SEALED_DATA_FILE`" ]; then
  echo "Seal/Unseal failed"
  exit 1
fi

tss2 delete --path=$KEY_PATH
printf "$SEAL_DATA" | tss2 createseal --path=$KEY_PATH --policyPath=$POLICY_PCR --type="noDa" \
    --data=- --authValue=""
UNSEALED_DATA=$(tss2 unseal --path=$KEY_PATH --data=- | xxd)

V1=$(printf "$SEAL_DATA" | xxd)
V2=$UNSEALED_DATA

if [ "$V1" != "$V2" ]; then
  echo "Seal/Unseal failed"
  exit 1
fi

expect <<EOF
# Try with missing path
spawn tss2 unseal --data=$UNSEALED_DATA_FILE --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

# Unseal with password
tss2 delete --path=$KEY_PATH
tss2 createseal --path=$KEY_PATH --data=$SEALED_DATA_FILE --authValue="abc"
printf "" > $UNSEALED_DATA_FILE
expect <<EOF
spawn tss2 unseal --path=$KEY_PATH --data=$UNSEALED_DATA_FILE --force
expect "Authorize object : "
send "abc\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
    send_user "Authorization failed\n"
    exit 1
}
EOF

V1=$(printf "$SEAL_DATA" | xxd)
V2=$"`xxd $UNSEALED_DATA_FILE`"

if [ "$V1" != "$V2" ]; then
  echo "Seal/Unseal failed"
  exit 1
fi


# Try with missing type
tss2 delete --path=$KEY_PATH
tss2 createseal --path $KEY_PATH --data=$SEALED_DATA_FILE --authValue=""
# Try with missing data
tss2 unseal --path=$KEY_PATH --force

# Try with size parameter
tss2 delete --path $KEY_PATH

expect <<EOF
# Try with size and data
spawn tss2 createseal --path $KEY_PATH --data $UNSEALED_DATA_FILE --size 6 --authValue ""
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong size
spawn tss2 createseal --path $KEY_PATH  --size abc --authValue ""
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong size
spawn tss2 createseal --path $KEY_PATH  --size 4294967296 --authValue ""
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tss2 createseal --path $KEY_PATH --size 15 --authValue ""
tss2 unseal --path $KEY_PATH --data $UNSEALED_DATA_FILE --force

wc -c $UNSEALED_DATA_FILE | awk '{print $1}'> $COUNT_FILE

if [ "$(< $COUNT_FILE)" !=  "15" ]; then
  echo "Wrong size"
  exit 99
fi

printf "" > $SEALED_DATA_FILE
expect <<EOF
# Try with empty seal file
spawn tss2 createseal --path $KEY_PATH --data $SEALED_DATA_FILE --authValue ""
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF


exit 0
