# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

start_up

alg_pem_load=ecc
pem_parent=prim
pem_file=mykey
Pem_persistent_parent=0x81100000

cleanup() {

  rm -f $file_load_key_pub $file_load_key_priv $file_load_key_name \
  $file_load_key_ctx

  tpm2 evictcontrol -Q -Co -c $Handle_parent 2>/dev/null || true

  if [ $(ina "$@" "keep_ctx") -ne 0 ]; then
    rm -f $file_primary_key_ctx
  fi

  if [ $(ina "$@" "no-shut-down") -ne 0 ]; then
          shut_down
  fi
}
trap cleanup EXIT

cleanup "no-shut-down"

tpm2 clear

# test to check negative parent in TSS pem file

tpm2 createprimary -G $alg_pem_load -C o \
-a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda" \
-c $pem_parent.ctx

tpm2 create -C $pem_parent.ctx -u $pem_file.pub -r $pem_file.priv

tpm2 evictcontrol -C o -c $pem_parent.ctx $Pem_persistent_parent

tpm2 encodeobject -C $Pem_persistent_parent -u $pem_file.pub \
-r $pem_file.priv -o $pem_file.pem

tpm2 load -r $pem_file.pem -c $pem_file.ctx

PARENTVAL=`openssl asn1parse -in $pem_file.pem -inform pem | awk '{print $7}'`
if egrep -q "^:-[0-9a-fA-F]{8}" <<< "$PARENTVAL"
then
  echo "Fail: Parent value is negative"
  exit 1
fi

exit 0

cleanup "no-shut-down"
