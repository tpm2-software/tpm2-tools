# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
  rm -f primary.ctx decrypt.ctx key.pub key.priv key.name decrypt.out \
        encrypt.out secret.dat key.dat evict.log primary.ctx key.ctx

  if [ "$1" != "no-shut-down" ]; then
      shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear -Q

tpm2_createprimary -Q -C e -g sha256 -G rsa -c primary.ctx

tpm2_create -Q -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx

tpm2_load -Q -C primary.ctx  -u key.pub  -r key.priv -n key.name -c key.dat

# Load the context into a specific handle, delete it
tpm2_evictcontrol -Q -c key.dat 0x81010003

tpm2_evictcontrol -Q -c 0x81010003 0x81010003

# Load the context into a specific handle, delete it without an explicit -p
tpm2_evictcontrol -Q -C o -c key.dat 0x81010003

tpm2_evictcontrol -Q -C o -c 0x81010003

# Load the context into an available handle, delete it
tpm2_evictcontrol -C o -c key.dat > evict.log
phandle=$(yaml_get_kv evict.log "persistent-handle")
tpm2_evictcontrol -Q -C o -c $phandle

yaml_verify evict.log

# verify that platform hierarchy auto selection for persistent handle works
tpm2_createprimary -C p -c primary.ctx
tpm2_create -C primary.ctx -c key.ctx
tpm2_evictcontrol -C p -c key.ctx > evict.log

phandle=$(yaml_get_kv evict.log persistent-handle)
tpm2_evictcontrol -C p -c $phandle

exit 0
