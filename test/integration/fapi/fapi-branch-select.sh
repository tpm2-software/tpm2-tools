
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

KEY_PATH="HS/SRK/mySignKey"
POLICY_SIGN_KEY_PATH="HS/SRK/myPolicySignKey"
PCR_POLICY_DATA=$TEMP_DIR/pol_pcr16_0.json
AUTHORIZE_POLICY_DATA=$TEMP_DIR/pol_authorize_ref.json
POLICY_PCR=policy/pcr-policy
POLICY_PCR2=policy/pcr-policy2
POLICY_AUTHORIZE=policy/authorize-policy
SIGNATURE_FILE=$TEMP_DIR/signature.file
PUBLIC_KEY_FILE=$TEMP_DIR/public_key.file
DIGEST_FILE=$TEMP_DIR/digest.file
echo -n 01234567890123456789012345678901 > $DIGEST_FILE

POLICY_REF=$TEMP_DIR/policy_ref.file
echo 'f0f1f2f3f4f5f6f7f8f9' | xxd -r -p > $POLICY_REF

PADDINGS="RSA_PSS"

tss2 provision

tss2 import --path=$POLICY_PCR --importData=$PCR_POLICY_DATA

tss2 import --path=$POLICY_PCR2 --importData=$PCR_POLICY_DATA

tss2 import --path=$POLICY_AUTHORIZE --importData=$AUTHORIZE_POLICY_DATA

tss2 createkey --path=$POLICY_SIGN_KEY_PATH --type="noDa, sign" --authValue=""

tss2 authorizepolicy --keyPath=$POLICY_SIGN_KEY_PATH --policyPath=$POLICY_PCR \
    --policyRef=$POLICY_REF

tss2 authorizepolicy --keyPath=$POLICY_SIGN_KEY_PATH --policyPath=$POLICY_PCR2 \
    --policyRef=$POLICY_REF

tss2 createkey --path=$KEY_PATH --type="noDa, sign" \
    --policyPath=$POLICY_AUTHORIZE --authValue=""

expect <<EOF
# Check if system asks for branch selection
spawn tss2 sign --keyPath=$KEY_PATH --padding=$PADDINGS --digest=$DIGEST_FILE \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
expect {
    "Your choice: " {
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

expect <<EOF
# Selecting wrong branch
spawn tss2 sign --keyPath=$KEY_PATH --padding=$PADDINGS --digest=$DIGEST_FILE \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
expect {
    "Your choice: " {
    } eof {
        send_user "The system has not asked for branch selection\n"
        exit 1
    }
}
send "4\r"
expect {
    "The entered integer must be positive and less than 3." {
    } eof {
        send_user "The system has not responded as expected\n"
        exit 1
    }
}
EOF

exit 0
