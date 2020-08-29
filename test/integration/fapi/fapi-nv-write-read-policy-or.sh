set -e
source helpers.sh

start_up

CRYPTO_PROFILE="ECC"
setup_fapi $CRYPTO_PROFILE

function cleanup {
    tss2 delete --path=/
    shut_down
}

trap cleanup EXIT

PW=abc
NV_PATH=/nv/Owner/myNV
DATA_WRITE_FILE=$TEMP_DIR/nv_write_data.file
DATA_READ_FILE=$TEMP_DIR/nv_read_data.file
POLICY_NV_DATA=$TEMP_DIR/pol_nv_read_write.json
POLICY_NV=/policy/nv_read_write
LOG_FILE=$TEMP_DIR/log.file
touch $LOG_FILE
PW=abc

tss2 provision

echo test > $DATA_WRITE_FILE

tss2 import -i $POLICY_NV_DATA -p $POLICY_NV
tss2 createnv -p $NV_PATH -P $POLICY_NV -s 16 --authValue=$PW

echo "Write with write policy"
expect <<EOF
# Check if system asks for branch selection
spawn sh -c "tss2 nvwrite --nvPath=$NV_PATH --data=$DATA_WRITE_FILE> $LOG_FILE"
expect -re {
    "Select a branch.*" {
    } eof {
        send_user "The system has not asked for branch selection\n"
        exit 1
    }
    }
    send "1\r"
    set ret [wait]
    if {[lindex \$ret 2]} {
        send_user "Command failed\n"
        exit 1
    }
EOF

echo "Read with read policy."
expect <<EOF
spawn sh -c "tss2 nvread --nvPath=$NV_PATH --data=$DATA_READ_FILE> $LOG_FILE"
expect -re {
    "Select a branch.*" { }
    eof {
        send_user "The system has not asked for branch selection\n"
        exit 1
    }
    }
send "2\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
    set file [open $LOG_FILE r]
        send_user "Command failed\n"
        exit 1
    }
EOF

echo "Write with read policy should fail."
expect <<EOF
# Check if system asks for branch selection
spawn sh -c "tss2 nvwrite --nvPath=$NV_PATH --data=$DATA_WRITE_FILE> $LOG_FILE"
expect -re {
    "Select a branch.*" {
    } eof {
        send_user "The system has not asked for branch selection\n"
        exit 1
    }
    }
    send "2\r"
    set ret [wait]
    if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
        send_user "Command failed\n"
        exit 1
    }
EOF

echo "Read with write policy should fail."
expect <<EOF
spawn sh -c "tss2 nvread --nvPath=$NV_PATH --data=$DATA_READ_FILE> $LOG_FILE"
expect -re {
    "Select a branch.*" {
    } eof {
        send_user "The system has not asked for branch selection\n"
        exit 1
    }
    }
    send "1\r"
    set ret [wait]
    if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    set file [open $LOG_FILE r]
        send_user "Command failed\n"
        exit 1
    }
EOF

tss2 delete --path=$NV_PATH

if [[ "`cat $LOG_FILE`" == $SANITIZER_FILTER ]]; then
  echo "Error: AddressSanitizer triggered."
  cat $LOG_FILE
  exit 1
fi

exit 0

