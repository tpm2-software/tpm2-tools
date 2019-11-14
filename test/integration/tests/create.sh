# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
  rm -f key.pub key.priv policy.bin out.pub key.ctx

  if [ $(ina "$@" "keep-context") -ne 0 ]; then
    rm -f context.out
  fi

  rm -f key*.ctx out.yaml

  if [ $(ina "$@" "no-shut-down") -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_createprimary -Q -C o -g sha1 -G rsa -c context.out

# Keep the algorithm specifiers mixed to test friendly and raw
# values.
for gAlg in `populate_hash_algs`; do
    for GAlg in rsa keyedhash ecc aes; do
        echo "tpm2_create -Q -C context.out -g $gAlg -G $GAlg -u key.pub \
        -r key.priv"
        tpm2_create -Q -C context.out -g $gAlg -G $GAlg -u key.pub -r key.priv
        cleanup "keep-context" "no-shut-down"
    done
done

cleanup "keep-context" "no-shut-down"

policy_orig=f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988
echo "$policy_orig" | xxd -r -p > policy.bin

tpm2_create -C context.out -g sha256 -G rsa -L policy.bin -u key.pub \
-r key.priv -a 'sign|fixedtpm|fixedparent|sensitivedataorigin' > out.pub

policy_new=$(yaml_get_kv out.pub "authorization policy")

test "$policy_orig" == "$policy_new"

#
# Test the extended format specifiers
#
# aes128cfb (mandatory for PCClient TPMs)
tpm2_create -Q -C context.out -g sha256 -G aes128cfb -u key.pub -r key.priv
tpm2_load -Q -C context.out -u key.pub -r key.priv -c key1.ctx
tpm2_readpublic -c key1.ctx > out.yaml
keybits=$(yaml_get_kv out.yaml "sym-keybits")
mode=$(yaml_get_kv out.yaml "sym-mode" "value")
test "$keybits" -eq "128"
test "$mode" == "cfb"

# aes256ofb (if supported)
if is_alg_supported aes256ofb; then
  mode="$(populate_alg_modes $strongest_aes | head -n1)" # e.g. aes128ecb
  tpm2_create -Q -C context.out -g sha256 -G aes256ofb -u key.pub -r key.priv
  tpm2_load -Q -C context.out -u key.pub -r key.priv -c key2.ctx
  tpm2_readpublic -c key2.ctx > out.yaml
  keybits=$(yaml_get_kv out.yaml "sym-keybits")
  mode=$(yaml_get_kv out.yaml "sym-mode" "value")
  test "$keybits" -eq "256"
  test "$mode" == "ofb"
fi

exit 0

#
# Test scheme support
#

for alg in "rsa1024:rsaes" "ecc384:ecdaa4-sha256"; do
  if is_alg_supported $alg; then
    tpm2_create -Q -C context.out -g sha256 -G "$alg" -u key.pub -r key.priv
  fi
done

# Test createloaded support
tpm2_create -C context.out -u key.pub -r key.priv -c key.ctx
tpm2_readpublic -c key.ctx 2>/dev/null

# Test that creation data has the specified outside info
tpm2_createprimary -C o -c prim.ctx -Q

dd if=/dev/urandom of=outside.info bs=1 count=32
tpm2_create -C prim.ctx -u key.pub -r key.priv --creation-data creation.data \
-q outside.info -Q

xxd -p creation.data | tr -d '\n' | grep `xxd -p outside.info | tr -d '\n'`

# Test that selected pcrs digest is present in the creation data
tpm2_pcrread sha256:0 -o pcr_data.bin

tpm2_create -C prim.ctx -u key.pub -r key.priv --creation-data creation.data \
-l sha256:0 -Q

xxd -p creation.data | tr -d '\n' | \
grep `cat pcr_data.bin | openssl dgst -sha256 -binary | xxd -p | tr -d '\n'`

exit 0
