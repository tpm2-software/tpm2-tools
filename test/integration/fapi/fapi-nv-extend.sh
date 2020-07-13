
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

NV_PATH=/nv/Owner/NvExtend
DATA_EXTEND_FILE=$TEMP_DIR/nv_extend.data
DATA_READ_FILE=$TEMP_DIR/nv_read.data
LOG_DATA=$TEMP_DIR/log.data
READ_LOG_DATA=$TEMP_DIR/read_log.data
EMPTY_FILE=$TEMP_DIR/empty.file
BIG_FILE=$TEMP_DIR/big_file.file

LOG_FILE=$TEMP_DIR/log.file
touch $LOG_FILE

echo -n 01234567890123456789 > $DATA_EXTEND_FILE
echo -n 01234567890123456789 > $LOG_DATA

tss2 provision

tss2 createnv --path=$NV_PATH --type="noDa, pcr" --size=0 --authValue=""

tss2 nvextend --nvPath=$NV_PATH --data=$DATA_EXTEND_FILE --logData=$LOG_DATA

echo "tss2 nvextend with EMPTY_FILE data" # Expected to succeed
tss2 nvextend --nvPath=$NV_PATH --data=$EMPTY_FILE --logData=$LOG_DATA

echo "tss2 nvextend with BIG_FILE data" # Expected to fail
expect <<EOF
spawn sh -c "tss2 nvextend --nvPath=$NV_PATH --data=$BIG_FILE \
  --logData=$LOG_DATA 2> $LOG_FILE"
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

echo "tss2 nvextend with EMPTY_FILE logData" # Expected to fail
expect <<EOF
spawn sh -c "tss2 nvextend --nvPath=$NV_PATH --data=$DATA_EXTEND_FILE \
    --logData=$EMPTY_FILE 2> $LOG_FILE"
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

echo "tss2 nvextend with BIG_FILE logData" # Expected to fail
expect <<EOF
spawn sh -c "tss2 nvextend --nvPath=$NV_PATH --data=$DATA_EXTEND_FILE0 \
    --logData=$BIG_FILE 2> $LOG_FILE"
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

tss2 nvread --nvPath=$NV_PATH --data=$DATA_READ_FILE --logData=$READ_LOG_DATA

if [ ! -f $READ_LOG_DATA ]; then
    echo "No log data returned"
    exit 1
fi

expect <<EOF
# Try with missing nvPath
spawn tss2 nvextend --data=$DATA_EXTEND_FILE --logData=$LOG_DATA
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing data
spawn tss2 nvextend --nvPath=$NV_PATH --logData=$LOG_DATA
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdin
spawn tss2 nvextend --nvPath=$NV_PATH --data=- --logData=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdin
spawn tss2 nvextend --nvPath $NV_PATH --data - --logData -
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
