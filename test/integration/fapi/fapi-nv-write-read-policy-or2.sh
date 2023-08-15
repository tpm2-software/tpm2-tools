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
POLICY_PWD_NV_DATA=$TEMP_DIR/pol_pwd_nv_read_write.json
POLICY_PWD_NV=/policy/pwd_nv_read_write
LOG_FILE=$TEMP_DIR/log.file
touch $LOG_FILE
PW=abc

tss2 provision

echo test > $DATA_WRITE_FILE

tss2 import -i $POLICY_PWD_NV_DATA -p $POLICY_PWD_NV
tss2 createnv -p $NV_PATH -P $POLICY_PWD_NV -s 16 --authValue=$PW

echo "Write without password but policy write."
expect <<EOF
spawn sh -c "tss2 nvwrite --nvPath=$NV_PATH --data=$DATA_WRITE_FILE> $LOG_FILE"
set timout 0
expect -re {
    "Select a branch.*" { }
    eof {
        send_user "The system has not asked for branch selection\n"
        exit 1
    }
    }
send "2\r"
expect -re {
    "Your choi.*" { }
    eof {
        send_user "The system did not comment selection\n"
        exit 1
    }
    }
expect -re {
    "Select.*" { }
    eof {
        send_user "The system has not asked for password\n"
        exit 1
    }
    }
send "1\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
    send_user "Using interactive prompt has failed\n"
    exit 1
}
EOF

echo "Write with password policy"
expect <<EOF
spawn sh -c "tss2 nvwrite --nvPath=$NV_PATH --data=$DATA_WRITE_FILE> $LOG_FILE"
set timout 0
expect -re {
    "Select a branch.*" { }
    eof {
        send_user "The system has not asked for branch selection\n"
        exit 1
    }
    }
send "1\r"
expect -re {
    "Your choi.*" { }
    eof {
        send_user "The system did not comment selection\n"
        exit 1
    }
    }
expect -re {
    "Authorize.*" { }
    eof {
        send_user "The system has not asked for password\n"
        exit 1
    }
    }
send "$PW\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
    send_user "Using interactive prompt has failed\n"
    exit 1
}
EOF

echo "Read with password policy"
expect <<EOF
spawn sh -c "tss2 nvread --nvPath=$NV_PATH --data=$DATA_READ_FILE > $LOG_FILE"
set timout 0
expect -re {
    "Select a branch.*" { }
    eof {
        send_user "The system has not asked for branch selection\n"
        exit 1
    }
    }
send "1\r"
expect -re {
    "Your choi.*" { }
    eof {
        send_user "The system did not comment selection\n"
        exit 1
    }
    }
expect -re {
    "Authorize.*" { }
    eof {
        send_user "The system has not asked for password\n"
        exit 1
    }
    }
send "$PW\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
    send_user "Using interactive prompt has failed\n"
    exit 1
}
EOF

echo "Write with wrong password should fail"
expect <<EOF
# Check if system asks for branch selection
spawn sh -c "tss2 nvwrite --nvPath=$NV_PATH --data=$DATA_WRITE_FILE> $LOG_FILE"
set timout 0
expect -re {
    "Select a branch.*" { }
    eof {
        send_user "The system has not asked for branch selection\n"
        exit 1
    }
    }
send "1\r"
expect -re {
    "Your choi.*" { }
    eof {
        send_user "The system did not comment selection\n"
        exit 1
    }
    }
expect -re {
    "Authorize.*" { }
    eof {
        send_user "The system has not asked for password\n"
        exit 1
    }
    }
send "XXXXX\r"
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Using interactive prompt has failed\n"
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

