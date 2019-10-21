# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
  rm -f primary.ctx decrypt.ctx key.pub key.priv key.name decrypt.out \
        encrypt.out secret.dat key.dat evict.log

  if [ "$1" != "no-shut-down" ]; then
      shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear -Q

tpm2_createprimary -Q -C p -c primary.ctx

tpm2_create -Q -C primary.ctx -u key.pub -r key.priv

tpm2_load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c key.ctx

tpm2_flushcontext -t

#
# Test that the object cannot be loaded after change the Platform seed
# which causes all transient objects created under the platform hierarchy
# to be invalidated.
#
tpm2_changepps

trap - ERR

tpm2_load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c key.ctx

exit 0
