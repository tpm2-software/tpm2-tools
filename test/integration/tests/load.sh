# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

start_up

alg_primary_obj=sha256
alg_primary_key=rsa
alg_create_obj=sha256
alg_create_key=hmac

alg_load=sha1

alg_pem_load=ecc
pem_parent=prim
pem_file=mykey

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_load_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_load_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_load_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-\
"$alg_create_obj"_"$alg_create_key"
file_load_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-\
"$alg_create_obj"_"$alg_create_key"
file_load_output=load_"$file_load_key_ctx"

Handle_parent=0x81010018
Handle_ek_load=0x81010017
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

#####file test

tpm2 createprimary -R -Q -C e -g $alg_primary_obj -G $alg_primary_key \
-c $file_primary_key_ctx

tpm2 create -R -Q -g $alg_create_obj -G $alg_create_key -u $file_load_key_pub \
-r $file_load_key_priv -C $file_primary_key_ctx

tpm2 load -R -Q -C $file_primary_key_ctx -u $file_load_key_pub \
-r $file_load_key_priv -n $file_load_key_name -c $file_load_key_ctx

#####handle test

cleanup "keep_ctx" "no-shut-down"

tpm2 evictcontrol -Q -C o -c $file_primary_key_ctx $Handle_parent

tpm2 create -Q -C $Handle_parent -g $alg_create_obj -G $alg_create_key \
-u $file_load_key_pub  -r $file_load_key_priv

tpm2 load -Q -C $Handle_parent -u $file_load_key_pub -r $file_load_key_priv \
-n $file_load_key_name -c $file_load_key_ctx

cleanup "no-shut-down"

#####pem test - persistent parent

tpm2 createprimary -G $alg_pem_load -C o \
-a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda" \
-c $pem_parent.ctx

tpm2 create -C $pem_parent.ctx -u $pem_file.pub -r $pem_file.priv

tpm2 evictcontrol -C o -c $pem_parent.ctx $Pem_persistent_parent

tpm2 encodeobject -C $Pem_persistent_parent -u $pem_file.pub \
-r $pem_file.priv -o $pem_file.pem

tpm2 load -r $pem_file.pem -c $pem_file.ctx

cleanup "no-shut-down"

#####pem test - non-persistent parent

tpm2 createprimary -G $alg_pem_load -C o \
-a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda" \
-c $pem_parent.ctx

tpm2 create -C $pem_parent.ctx -u $pem_file.pub -r $pem_file.priv

tpm2 encodeobject -C $pem_parent.ctx -u $pem_file.pub -r $pem_file.priv \
-o $pem_file.pem

tpm2 load -r $pem_file.pem -c $pem_file.ctx

exit 0
