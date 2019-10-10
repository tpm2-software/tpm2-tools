#!/bin/bash

set -e
source helpers.sh

start_up

setup_fapi

function cleanup {
    tss2_delete --path /
    shut_down
}

trap cleanup EXIT

KEY_PATH=HS/SRK/myRSASign

tss2_provision

tss2_createkey --path $KEY_PATH --type "noDa, sign" --authValue ""

tss2_list

PROFILE_NAME=$( tss2_list --searchPath= --pathList=- | cut -d "/" -f2 )
SIGN_OBJECT=/$PROFILE_NAME/$KEY_PATH

if [ `tss2_list --searchPath=$KEY_PATH --pathList=-` != $SIGN_OBJECT ]; then
  echo "tss2_list single object failed"
  exit 1
fi

exit 0