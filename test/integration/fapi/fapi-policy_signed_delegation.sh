# In this test a backend issues two policies to a user "A":
#   1. A user policy that allows "A" to authorize key usage
#   2. An offline delegation policy that allows "A" to delegate his access rights
#      two user "B" without further interaction with the backend. 

# set -e
source helpers.sh

start_up

CRYPTO_PROFILE="RSA"
setup_fapi $CRYPTO_PROFILE

# Extract value from JSON file
function jsonValue {
    KEY=$1
    num=$2
    awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'$KEY'\042/){print $(i+1)}}}' | tr -d '"' | sed -n ${num}p
}

function cleanup {
    # In case the test is skipped, no key is created and a
    # failure is expected here. Therefore, we need to pass a successful
    # execution in any case
    tss2 delete --path=/ && true
    shut_down
}

trap cleanup EXIT

# The delegation test needs at least the commit
# b843960b6e601a786b469832392dc0a12e13cf34 of TSS to be executed successfully.
# This commit will be introduced in version > 3.0.3. Will skip the test if
# version is below.
if [[ "$(echo $TSS_VERSION | sed 's/[^0-9]*//g')" -le "303" && "$TSS_VERSION" != "master" ]]; then
    echo "TSS version does not support test"
    exit 077
fi

PATH_REVOCATION="/nv/Owner/ctr"
PATH_FEATURE_KEY_SIGN="HS/SRK/signkey"

# Backend Policies
POLICY_AUTH_BACKEND_PEM="pol_authorize_backend_pem.json"
PATH_POL_AUTHORIZE="/policy/pol_authorize"

# User Policies
POLICY_USER="pol_user.json"
PATH_POL_USER="/policy/pol_user"
POLICY_TO_BE_SIGNED_USER="pol_to_be_signed_user.json"
POLICY_AUTHORIZED_USER="pol_authorized_user.json"
PATH_POL_AUTHORIZED_USER="/policy/pol_authorized_user"

# Offline Delegation Policy
POLICY_OFFLINE_DELEGATION="pol_offline_delegation.json"
PATH_POL_OFFLINE_DELEGATION="/policy/pol_offline_delegation"
POLICY_TO_BE_SIGNED_OFFLINE_DELEGATION="pol_to_be_signed_offline_delegation.json"
POLICY_AUTHORIZED_OFFLINE_DELEGATION="pol_authorized_offline_delegation.json"
PATH_POL_AUTHORIZED_OFFLINE_DELEGATION="/policy/pol_authorized_offline_delegation"

# Sub Policy
POLICY_SUB_POLICY="pol_sub_policy.json"
PATH_POL_SUB_POLICY="/policy/pol_sub_policy"
POLICY_TO_BE_SIGNED_SUB_POLICY="pol_to_be_signed_sub_policy.json"
POLICY_AUTHORIZED_SUB_POLICY="pol_authorized_sub_policy.json"
PATH_POL_AUTHORIZED_SUB_POLICY="/policy/pol_authorized_sub_policy"

# Data for Authorization
TEST_SIGNATURE_FILE=$TEMP_DIR/test_signature.file
OUTPUT_FILE=$TEMP_DIR/data2sign.file
SIGNATURE_FILE=$TEMP_DIR/signature.file

search_string="\"policy\":["

LOG_FILE=$TEMP_DIR/log.file
touch $LOG_FILE

EMPTY_FILE=$TEMP_DIR/empty.file
BIG_FILE=$TEMP_DIR/big_file.file

# 0. Create Keys

openssl ecparam -name secp256r1 -genkey -noout -out $TEMP_DIR/key_backend_priv.pem
openssl ec -in $TEMP_DIR/key_backend_priv.pem -pubout -out $TEMP_DIR/key_backend_pub.pem

openssl ecparam -name secp256r1 -genkey -noout -out $TEMP_DIR/key_user_priv.pem
openssl ec -in $TEMP_DIR/key_user_priv.pem -pubout -out $TEMP_DIR/key_user_pub.pem

openssl ecparam -name secp256r1 -genkey -noout -out $TEMP_DIR/key_delegated_priv.pem
openssl ec -in $TEMP_DIR/key_delegated_priv.pem -pubout -out $TEMP_DIR/key_delegated_pub.pem

# 1. Create necessary policy templates

## Backend Authorization Policy
cat <<EOF > $TEMP_DIR/$POLICY_AUTH_BACKEND_PEM
{
    "description":"Initial Authorization Policy",
    "policy":[
        {
            "type": "POLICYAUTHORIZE",
            "policyRef": [ 0, 2, 3, 4, 5 ],
            "keyPEM": "`cat $TEMP_DIR/key_backend_pub.pem`"
        }
    ]
}
EOF

# USER POLICY
cat <<EOF > $TEMP_DIR/$POLICY_USER
{
  "description": "User Policy",
  "policy": [
    {
      "type": "NV",
      "nvPath": "`echo $PATH_REVOCATION`",
      "operandB": "0000000000000002",
      "operation": "neq"
    },
    {
      "type": "CounterTimer",
      "operandB": "5000",
      "operation": "signed_lt"
    },
    {
      "type": "Signed",
      "keyPEM": "`cat $TEMP_DIR/key_user_pub.pem`",
      "keyPEMhashAlg": "SHA256"
    }
  ]
}
EOF

## Offline Delegation Policy
cat <<EOF > $TEMP_DIR/$POLICY_OFFLINE_DELEGATION
{
    "description":"Offline Delegation",
    "policy":[
        {
            "type": "POLICYAUTHORIZE",
            "policyRef": [ 5, 2, 3, 4, 5 ],
            "keyPEM": "`cat $TEMP_DIR/key_user_pub.pem`"
        },
        {
          "type": "NV",
          "nvPath": "`echo $PATH_REVOCATION`",
          "operandB": "0000000000000002",
          "operation": "neq"
        }
    ]
}
EOF

## SUB POLICY (will be signed by user)
cat <<EOF > $TEMP_DIR/$POLICY_SUB_POLICY
{
  "description": "Sub Policy",
  "policy": [
    {
      "type": "CounterTimer",
      "operandB": "5000",
      "operation": "signed_lt"
    },
    {
      "type": "Signed",
      "keyPEM": "`cat $TEMP_DIR/key_delegated_pub.pem`",
      "keyPEMhashAlg": "SHA256"
    }
  ]
}
EOF



# 2. Create Setting
tss2 provision

## Create feature key with authorize policy
tss2 import --path $PATH_POL_AUTHORIZE --importData $TEMP_DIR/$POLICY_AUTH_BACKEND_PEM
tss2 createkey --path $PATH_FEATURE_KEY_SIGN --type="sign, noda, 0x81000002" --policyPath $PATH_POL_AUTHORIZE --authValue ""

## Create revocation counter
tss2 createnv --path $PATH_REVOCATION --type=counter --authValue ""
tss2 nvincrement --nvPath $PATH_REVOCATION

# 3. Backend creates User Policy and Offline Delegation Policy
## 3.1 Get digests of policies and sign for authorization

### Sign digest of User Policy with key_backend_priv
tss2 import --path $PATH_POL_USER --importData $TEMP_DIR/$POLICY_USER
tss2 createkey --path HS/SRK/tmpkey --policyPath $PATH_POL_USER --type="sign, noda" --authValue ""
tss2 exportpolicy --path HS/SRK/tmpkey --jsonPolicy $TEMP_DIR/$POLICY_TO_BE_SIGNED_USER -f
tss2 delete --path HS/SRK/tmpkey
tss2 delete --path $PATH_POL_USER

digest_user=`cat $TEMP_DIR/$POLICY_TO_BE_SIGNED_USER | jsonValue "digest" 1` 
digest_user="$digest_user""0002030405"

echo -n $digest_user | \
    xxd -r -p | openssl dgst -sha256 -sign $TEMP_DIR/key_backend_priv.pem -hex | \
    sed 's/^.* //' > signed_user_policy.sig

### Sign digest of Offline Delegation Policy with key_backend_priv
tss2 import --path $PATH_POL_OFFLINE_DELEGATION --importData $TEMP_DIR/$POLICY_OFFLINE_DELEGATION
tss2 createkey --path HS/SRK/tmpkey --policyPath $PATH_POL_OFFLINE_DELEGATION --type="sign, noda" --authValue ""
tss2 exportpolicy --path HS/SRK/tmpkey --jsonPolicy $TEMP_DIR/$POLICY_TO_BE_SIGNED_OFFLINE_DELEGATION -f
tss2 delete --path HS/SRK/tmpkey
tss2 delete --path $PATH_POL_OFFLINE_DELEGATION

digest_offline_delegation=`cat $TEMP_DIR/$POLICY_TO_BE_SIGNED_OFFLINE_DELEGATION | jsonValue "digest" 1` 
digest_offline_delegation="$digest_offline_delegation""0002030405"

echo -n $digest_offline_delegation | \
    xxd -r -p | openssl dgst -sha256 -sign $TEMP_DIR/key_backend_priv.pem -hex | \
    sed 's/^.* //' > signed_policy_offline_delegation.sig

### Sign digest of Sub Policy with key_user_priv
tss2 import --path $PATH_POL_SUB_POLICY --importData $TEMP_DIR/$POLICY_SUB_POLICY
tss2 createkey --path HS/SRK/tmpkey --policyPath $PATH_POL_SUB_POLICY --type="sign, noda" --authValue ""
tss2 exportpolicy --path HS/SRK/tmpkey --jsonPolicy $TEMP_DIR/$POLICY_TO_BE_SIGNED_SUB_POLICY -f
tss2 delete --path HS/SRK/tmpkey
tss2 delete --path $PATH_POL_SUB_POLICY

digest_sub_policy=`cat $TEMP_DIR/$POLICY_TO_BE_SIGNED_SUB_POLICY | jsonValue "digest" 1` 
digest_sub_policy="$digest_sub_policy""0502030405"

echo -n $digest_sub_policy | \
    xxd -r -p | openssl dgst -sha256 -sign $TEMP_DIR/key_user_priv.pem -hex | \
    sed 's/^.* //' > signed_policy_sub_policy.sig


## 3.2 Create Authorized Policies from Template

### Create Authorized User Policy
POLICY_AUTH_TEMPLATE_USER=$(cat <<EOF
    "policyAuthorizations":[
        {
            "type": "pem",
            "policyRef": [ 0, 2, 3, 4, 5 ],
            "key": "`cat $TEMP_DIR/key_backend_pub.pem`",
            "signature": "`cat signed_user_policy.sig`"
        }
    ],
EOF
)

AUTHORIZED_POLICY_TMP=""
while read line; do
    # reading each line
    if [[ $search_string == $line ]]; then
        AUTHORIZED_POLICY_TMP="$AUTHORIZED_POLICY_TMP"$'\n'"$POLICY_AUTH_TEMPLATE_USER"
    fi
    AUTHORIZED_POLICY_TMP="$AUTHORIZED_POLICY_TMP"$'\n'"$line"
done < $TEMP_DIR/$POLICY_TO_BE_SIGNED_USER
AUTHORIZED_POLICY_TMP="$AUTHORIZED_POLICY_TMP"$'\n'"}"

echo "$AUTHORIZED_POLICY_TMP" > $TEMP_DIR/$POLICY_AUTHORIZED_USER


### Create Offline Delegation und Sub Policy

POLICY_AUTH_TEMPLATE_OFFLINE_DELEGATION=$(cat <<EOF
    "policyAuthorizations":[
        {
            "type": "pem",
            "policyRef": [ 0, 2, 3, 4, 5 ],
            "key": "`cat $TEMP_DIR/key_backend_pub.pem`",
            "signature": "`cat signed_policy_offline_delegation.sig`"
        }
    ],
EOF
)

CONCATENATED_POLICY=""
while read line; do
    # reading each line
    if [[ $search_string == $line ]]; then
        CONCATENATED_POLICY="$CONCATENATED_POLICY"$'\n'"$POLICY_AUTH_TEMPLATE_OFFLINE_DELEGATION"
    fi
    CONCATENATED_POLICY="$CONCATENATED_POLICY"$'\n'"$line"
done < $TEMP_DIR/$POLICY_TO_BE_SIGNED_OFFLINE_DELEGATION
CONCATENATED_POLICY="$CONCATENATED_POLICY"$'\n'"}"

echo "$CONCATENATED_POLICY" > $TEMP_DIR/$POLICY_AUTHORIZED_OFFLINE_DELEGATION

POLICY_AUTH_TEMPLATE_SUB_POLICY=$(cat <<EOF
    "policyAuthorizations":[
        {
            "type": "pem",
            "policyRef": [ 5, 2, 3, 4, 5 ],
            "key": "`cat $TEMP_DIR/key_user_pub.pem`",
            "signature": "`cat signed_policy_sub_policy.sig`"
        }
    ],
EOF
)

CONCATENATED_POLICY=""
while read line; do
    # reading each line
    if [[ $search_string == $line ]]; then
        CONCATENATED_POLICY="$CONCATENATED_POLICY"$'\n'"$POLICY_AUTH_TEMPLATE_SUB_POLICY"
    fi
    CONCATENATED_POLICY="$CONCATENATED_POLICY"$'\n'"$line"
done < $TEMP_DIR/$POLICY_TO_BE_SIGNED_SUB_POLICY
CONCATENATED_POLICY="$CONCATENATED_POLICY"$'\n'"}"

echo "$CONCATENATED_POLICY" > $TEMP_DIR/$POLICY_AUTHORIZED_SUB_POLICY

## 4. Authorize with authorized policies

### Create some digest data to sign
DIGEST_FILE=$TEMP_DIR/digest.file
echo -n 01234567890123456789 > $DIGEST_FILE

### Import the authorized policies
tss2 import --path $PATH_POL_AUTHORIZED_USER --importData $TEMP_DIR/$POLICY_AUTHORIZED_USER
tss2 import --path $PATH_POL_AUTHORIZED_OFFLINE_DELEGATION --importData $TEMP_DIR/$POLICY_AUTHORIZED_OFFLINE_DELEGATION
tss2 import --path $PATH_POL_AUTHORIZED_SUB_POLICY --importData $TEMP_DIR/$POLICY_AUTHORIZED_SUB_POLICY

## 4.1 User authorizes key usage with the user policy
echo "1. User authorizes key usage with the user policy"

expect -c "
  spawn tss2 sign --keyPath=$PATH_FEATURE_KEY_SIGN --digest=$DIGEST_FILE --signature=$TEST_SIGNATURE_FILE -f
  expect -re \"Select a branch for P_RSA2048SHA256/HS/SRK/signkey .* Your choice:\" {
    set branches [split \$expect_out(buffer) \"\n\"]
    set lstSize [llength \$branches]
    set index 0
    foreach branch \$branches {
      if {[regexp -nocase \"/policy/pol_authorized_user\" \$branch]} {
        send \"\$index\r\"
        break
      }
      incr index
    }
    if {\$index >= \$lstSize} {
      send_user \"\nError: Branch @ index \$index not found\n\"
      exit 1
    }
    expect \"Filename for nonce output: \" {
      send \"$OUTPUT_FILE\r\"
      expect \"Filename for signature input: \" {
        exec openssl dgst -sha256 -sign $TEMP_DIR/key_user_priv.pem -out $SIGNATURE_FILE $OUTPUT_FILE
        send \"$SIGNATURE_FILE\r\"
        send_user \"\n\"
      }
    }
    set ret [wait]
    if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
        send_user \"\n[lindex \$ret]\n\"
        send_user \"Command failed\n\"
        exit 1
    }
  }
"

## 4.2 Delegated User authorizes key usage with the offline delegation policy
echo "2. Delegated User authorizes key usage with the offline delegation policy"

expect -c "
    spawn tss2 sign --keyPath=$PATH_FEATURE_KEY_SIGN --digest=$DIGEST_FILE --signature=$TEST_SIGNATURE_FILE -f
    expect -re \"Select a branch for P_RSA2048SHA256/HS/SRK/signkey .* Your choice:\" {
      set branches [split \$expect_out(buffer) \"\n\"]
      set lstSize [llength \$branches]
      set index 0
      foreach branch \$branches {
        if {[regexp -nocase \"/policy/pol_authorized_offline_delegation\" \$branch]} {
          send \"\$index\r\"
          break
        }
        incr index
      }
      if {\$index >= \$lstSize} {
        send_user \"\nError: Branch @ index \$index not found\n\"
        exit 1
      }
      expect \"Filename for nonce output: \" {
          send \"$OUTPUT_FILE\r\"
          expect \"Filename for signature input: \" {
              exec openssl dgst -sha256 -sign $TEMP_DIR/key_delegated_priv.pem -out $SIGNATURE_FILE $OUTPUT_FILE
              send \"$SIGNATURE_FILE\r\"
              send_user \"\n\"
          }
      }
      set ret [wait]
      if {[lindex \$ret 2] || [lindex \$ret 3] != 0} {
          send_user \"\n[lindex \$ret]\n\"
          send_user \"Command failed 2\n\"
          exit 1
      }
  }
"

exit 0