# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
  tpm2 changeauth -c p -p testpassword 2>/dev/null || true

  rm -f primary.ctx key.pub key.priv key.ctx key.name

  if [ "$1" != "no-shut-down" ]; then
      shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear -Q

tpm2 createprimary -Q -C p -c primary.ctx

tpm2 create -Q -C primary.ctx -u key.pub -r key.priv

tpm2 load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c key.ctx

tpm2 flushcontext -t

#
# Test that the object cannot be loaded after change the Platform seed
# which causes all transient objects created under the platform hierarchy
# to be invalidated.
#
tpm2 changepps

trap - ERR

tpm2 load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c key.ctx

#
# Test with non null platform hierarchy auth
#
trap onerror ERR

tpm2 changeauth -c p testpassword

tpm2 createprimary -Q -C p -c primary.ctx -P testpassword

tpm2 create -Q -C primary.ctx -u key.pub -r key.priv

tpm2 changepps -p testpassword

trap - ERR

tpm2 load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c key.ctx

exit 0
