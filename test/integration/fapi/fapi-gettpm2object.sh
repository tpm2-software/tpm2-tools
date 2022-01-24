
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

NV_PATH=/nv/Owner/myNV
KEY_PATH=/HS/SRK/mykey
KEY_CONTEXT=$TEMP_DIR/mykey.ctx
DATA_FILE=$TEMP_DIR/data.file
NV_BLOB_FILE=$TEMP_DIR/myNV.blob
SIGNATURE_FILE=$TEMP_DIR/signature

echo -n 0123456789 > $DATA_FILE

tss2 provision

tss2 createkey --path=$KEY_PATH --type="noDa, sign" --authValue=""
tss2 gettpm2object -p $KEY_PATH --context $KEY_CONTEXT
tpm2 sign -c $KEY_CONTEXT -g sha256 -o $SIGNATURE_FILE $DATA_FILE
tss2 delete -p $KEY_PATH
tss2 createnv -p $NV_PATH -s 10 --authValue=""
echo -n ""|tss2 nvwrite -p $NV_PATH -i-
handle=$(tss2 gettpm2object -p $NV_PATH -c-)
tpm2 nvwrite -i $DATA_FILE $handle

exit 0
