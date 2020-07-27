
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

echo -n 01234567890123456789 > $DATA_EXTEND_FILE
echo -n 01234567890123456789 > $LOG_DATA

tss2 provision

tss2 createnv --path=$NV_PATH --type="noDa, pcr" --size=0 --authValue=""

tss2 nvextend --nvPath=$NV_PATH --data=$DATA_EXTEND_FILE --logData=$LOG_DATA

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
