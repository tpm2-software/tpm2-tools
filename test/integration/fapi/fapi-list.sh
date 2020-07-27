
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

KEY_PATH=HS/SRK/myRSASign

tss2 provision

tss2 createkey --path=$KEY_PATH --type="noDa, sign" --authValue=""

tss2 list

PROFILE_NAME=$( tss2 list --searchPath= --pathList=- | cut -d "/" -f2 )
SIGN_OBJECT=/$PROFILE_NAME/$KEY_PATH

if [ `tss2 list --searchPath=$KEY_PATH --pathList=-` != $SIGN_OBJECT ]; then
  echo "tss2_list single object failed"
  exit 1
fi

exit 0
