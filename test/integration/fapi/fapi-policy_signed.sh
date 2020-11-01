
# set -e
source helpers.sh

start_up

CRYPTO_PROFILE="RSA"
setup_fapi $CRYPTO_PROFILE

function cleanup {
    tss2 delete --path=/
    shut_down
}

trap cleanup EXIT

# openssl ecparam -name secp256r1 -genkey -noout -out key_priv.pem
# openssl ec -in key_priv.pem -pubout -out key_pub.pem

# -----BEGIN PUBLIC KEY-----
# MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAw+PKFksCw+ikD76l6BMeXfebcZx
# Gf8QGWT2MOy8tOfpe6m+6MUUm2GUijGPkvCTjtJPOJz//XMom+k+7OaWmA==
# -----END PUBLIC KEY-----

# -----BEGIN EC PRIVATE KEY-----
# MHcCAQEEICf0OXKKsPkEVR1jsPOKSQQJnJVimamLYwLDZwJDj7etoAoGCCqGSM49
# AwEHoUQDQgAEAw+PKFksCw+ikD76l6BMeXfebcZxGf8QGWT2MOy8tOfpe6m+6MUU
# m2GUijGPkvCTjtJPOJz//XMom+k+7OaWmA==
# -----END EC PRIVATE KEY-----


KEY_PATH_1=HS/SRK/mySignKey1
KEY_PATH_2=HS/SRK/mySignKey2
SIGN_POLICY_DATA=pol_signed.json
SIGN_POLICY_DATA_KEY_HINT=pol_signed_key_hint.json
POLICY_SIGNED=policy/policy-signed
POLICY_SIGNED_KEY_HINT=policy/policy-signed_key_hint
TEST_SIGNATURE_FILE=test_signature.file
SIGNATURE_FILE=signature.file
DIGEST_FILE=digest.file
PRIV_KEY_FILE=priv_key.file

LOG_FILE=$TEMP_DIR/log.file
touch $LOG_FILE

EMPTY_FILE=$TEMP_DIR/empty.file
BIG_FILE=$TEMP_DIR/big_file.file

# Setup Policy Signed
cat > $SIGN_POLICY_DATA_KEY_HINT <<EOF
{
    "description":"Description pol_signed",
    "policy":[
        {
            "type": "POLICYSIGNED",
            "keyPEM": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAw+PKFksCw+ikD76l6BMeXfebcZx\nGf8QGWT2MOy8tOfpe6m+6MUUm2GUijGPkvCTjtJPOJz//XMom+k+7OaWmA==\n-----END PUBLIC KEY-----",
            "keyPEMhashAlg": "SHA1",
            "publicKeyHint": "My Signature Key"
        }
    ]
}
EOF

cat > $SIGN_POLICY_DATA <<EOF
{
    "description":"Description pol_signed",
    "policy":[
        {
            "type": "POLICYSIGNED",
            "keyPEM": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAw+PKFksCw+ikD76l6BMeXfebcZx\nGf8QGWT2MOy8tOfpe6m+6MUUm2GUijGPkvCTjtJPOJz//XMom+k+7OaWmA==\n-----END PUBLIC KEY-----",
            "keyPEMhashAlg": "SHA1",
        }
    ]
}
EOF

# Write private pem key to file
cat > $PRIV_KEY_FILE <<EOF
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICf0OXKKsPkEVR1jsPOKSQQJnJVimamLYwLDZwJDj7etoAoGCCqGSM49
AwEHoUQDQgAEAw+PKFksCw+ikD76l6BMeXfebcZxGf8QGWT2MOy8tOfpe6m+6MUU
m2GUijGPkvCTjtJPOJz//XMom+k+7OaWmA==
-----END EC PRIVATE KEY-----
EOF

echo -n 01234567890123456789 > $DIGEST_FILE

tss2 provision

tss2 import --path=$POLICY_SIGNED --importData=$SIGN_POLICY_DATA

tss2 import --path=$POLICY_SIGNED_KEY_HINT --importData=$SIGN_POLICY_DATA_KEY_HINT

tss2 createkey --path $KEY_PATH_1 --type="sign, noda" \
  --policyPath $POLICY_SIGNED --authValue ""

tss2 createkey --path $KEY_PATH_2 --type="sign, noda" \
  --policyPath $POLICY_SIGNED_KEY_HINT --authValue ""

OUTPUT_FILE=$TEMP_DIR/data2sign.file

expect <<EOF
    spawn sh -c "tss2 sign --keyPath=$KEY_PATH_1 --digest=$DIGEST_FILE --signature=$TEST_SIGNATURE_FILE --force 2> $LOG_FILE"
    expect "Filename for nonce output: " {
        send "$OUTPUT_FILE\r"
        expect "Filename for signature input: " {
            exec openssl dgst -sha1 -sign $PRIV_KEY_FILE -out $SIGNATURE_FILE $OUTPUT_FILE
            send "$SIGNATURE_FILE\r"
            exp_continue
        }
    }
EOF

if grep "ERROR" $LOG_FILE > /dev/null
then
  cat $LOG_FILE
  exit 1
fi

expect <<EOF
    spawn sh -c "tss2 sign --keyPath=$KEY_PATH_2 --digest=$DIGEST_FILE --signature=$TEST_SIGNATURE_FILE --force 2> $LOG_FILE"
    expect "Filename for nonce output: " {
        send "$OUTPUT_FILE\r"
        expect "Filename for signature input: " {
            exec openssl dgst -sha1 -sign $PRIV_KEY_FILE -out $SIGNATURE_FILE $OUTPUT_FILE
            send "$SIGNATURE_FILE\r"
            exp_continue
        }
    }
EOF

if grep "ERROR" $LOG_FILE > /dev/null
then
  cat $LOG_FILE
  exit 1
fi

echo "sign callback with BIG_FILE" # Expected to fail
expect <<EOF
    spawn sh -c "tss2 sign --keyPath=$KEY_PATH_1 --digest=$DIGEST_FILE --signature=$TEST_SIGNATURE_FILE --force 2> $LOG_FILE"
    expect "Filename for nonce output: " {
        send "$OUTPUT_FILE\r"
        expect "Filename for signature input: " {
            exec openssl dgst -sha1 -sign $PRIV_KEY_FILE -out $SIGNATURE_FILE $OUTPUT_FILE
            send "$BIG_FILE\r"
            set ret [wait]
            if {[lindex \$ret 2] || [lindex \$ret 3] == 0} {
                send_user "\n[lindex \$ret]\n"
                send_user "Command not failed as expected\n"
                exit 1
            }
        }
        set ret [wait]
        if {[lindex \$ret 2] || [lindex \$ret 3] == 0} {
            set file [open $LOG_FILE r]
            set log [read \$file]
            close $file
            send_user "\n[lindex \$ret]\n"
            send_user "Command has not failed as expected\n"
            exit 1
        }
    }          
EOF

if [[ "`cat $LOG_FILE`" == $SANITIZER_FILTER ]]; then
  echo "Error: AddressSanitizer triggered."
  cat $LOG_FILE
  exit 1
fi

echo "sign callback with EMPTY_FILE" # Expected to fail
expect <<EOF  
    spawn sh -c "tss2 sign --keyPath=$KEY_PATH_1 --digest=$DIGEST_FILE --signature=$TEST_SIGNATURE_FILE --force 2> $LOG_FILE"
    expect "Filename for nonce output: " {
        send "$OUTPUT_FILE\r"
        expect "Filename for signature input: " {
            exec openssl dgst -sha1 -sign $PRIV_KEY_FILE -out $SIGNATURE_FILE $OUTPUT_FILE
            send "$EMPTY_FILE\r"
            set ret [wait]
            if {[lindex \$ret 2] || [lindex \$ret 3] == 0} {
                send_user "\n[lindex \$ret]\n"
                send_user "Command has not failed as expected\n"
                exit 1
            }
        }
        set ret [wait]
        if {[lindex \$ret 2] || [lindex \$ret 3] == 0} {
            set file [open $LOG_FILE r]
            set log [read \$file]
            close $file
            send_user "\n[lindex \$ret]\n"
            send_user "Command has not failed as expected\n"
            exit 1
        }
    }          
EOF

if [[ "`cat $LOG_FILE`" == $SANITIZER_FILTER ]]; then
  echo "Error: AddressSanitizer triggered."
  cat $LOG_FILE
  exit 1
fi

exit 0