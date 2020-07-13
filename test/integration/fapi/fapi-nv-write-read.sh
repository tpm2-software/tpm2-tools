
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

PW=abc
NV_PATH=/nv/Owner/myNVwrite
DATA_WRITE_FILE=$TEMP_DIR/nv_write_data.file
DATA_READ_FILE=$TEMP_DIR/nv_read_data.file
EMPTY_FILE=$TEMP_DIR/empty.file
BIG_FILE=$TEMP_DIR/big_file.file
LOG_FILE=$TEMP_DIR/log.file
touch $LOG_FILE

tss2 provision

echo 1234567890123456789 > $DATA_WRITE_FILE

tss2 createnv --path=$NV_PATH --type="noDa" --size=20 --authValue=""

tss2 nvwrite --nvPath=$NV_PATH --data=$DATA_WRITE_FILE

echo "tss2 nvwrite with EMPTY_FILE" # Expected to succeed
tss2 nvwrite --nvPath=$NV_PATH --data=$EMPTY_FILE

echo "tss2 nvwrite with BIG_FILE" # Expected to fail
expect <<EOF
spawn sh -c "tss2 nvwrite --nvPath=$NV_PATH --data=$BIG_FILE 2> $LOG_FILE"
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

tss2 nvread --nvPath=$NV_PATH --data=$DATA_READ_FILE --force

if [ `cat $DATA_READ_FILE` !=  `cat $DATA_WRITE_FILE` ]; then
  echo "Test without password: Strings are not equal"
  exit 99
fi

tss2 delete --path=$NV_PATH

tss2 createnv --path=$NV_PATH --type="noDa" --size=20 --authValue=$PW

expect <<EOF
# Check if system asks for auth value and provide it
spawn tss2 nvwrite --nvPath=$NV_PATH --data=$DATA_WRITE_FILE
expect {
    "Authorize object: " {
    } eof {
        send_user "The system has not asked for password\n"
        exit 1
    }
    }
    send "$PW\r"
    set ret [wait]
    if {[lindex \$ret 2] || [lindex \$ret 3]} {
        send_user "Passing password has failed\n"
        exit 1
    }
EOF

expect <<EOF
# Try with missing nvPath
spawn tss2 nvread --data=$DATA_READ_FILE --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing data
spawn tss2 nvread --nvPath=$NV_PATH  --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (1)
spawn tss2 nvread --nvPath=$NV_PATH --data=- --logData=- --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (1)
spawn tss2 nvread --nvPath $NV_PATH --data - --logData - --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing nvPath
spawn tss2 nvwrite --data=$DATA_WRITE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing data
spawn tss2 nvwrite --nvPath=$NV_PATH
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tss2 delete --path=$NV_PATH

NODA="noDa"
expect <<EOF
# Try interactive prompt
spawn tss2 createnv --path=$NV_PATH --type=$NODA --size=20
expect "Authorize object Password: "
send "$PW\r"
expect "Authorize object Retype password: "
send "$PW\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
    send_user "Using interactive prompt with password has failed\n"
    exit 1
}
EOF

# Try with missing type
tss2 delete --path=$NV_PATH
tss2 createnv --path=$NV_PATH --size=20 --authValue=$PW

# Try with size-0 supported types
tss2 delete --path=$NV_PATH
tss2 createnv --path=$NV_PATH --type="bitfield" --size=0 --authValue=$PW
tss2 delete --path=$NV_PATH
tss2 createnv --path=$NV_PATH --type="pcr" --size=0 --authValue=$PW
tss2 delete --path=$NV_PATH
tss2 createnv --path=$NV_PATH --type="counter" --size=0 --authValue=$PW
tss2 delete --path=$NV_PATH
tss2 createnv --path=$NV_PATH --type="bitfield" --authValue=$PW
tss2 delete --path=$NV_PATH
tss2 createnv --path=$NV_PATH --type="pcr" --authValue=$PW
tss2 delete --path=$NV_PATH
tss2 createnv --path=$NV_PATH --type="counter" --authValue=$PW
tss2 delete --path=$NV_PATH

expect <<EOF
# Try with missing size and no type
spawn tss2 createnv --path=$NV_PATH --authValue=$PW
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with size=0 and no type
spawn tss2 createnv --path=$NV_PATH --size=0 --authValue=$PW
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
