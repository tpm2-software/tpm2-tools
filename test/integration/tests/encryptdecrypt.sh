#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
  rm -f primary.ctx decrypt.ctx key.pub key.priv key.name \
        decrypt.out decrypt2.out encrypt.out encrypt2.out \
        secret.dat commands.cap secret2.dat iv.dat iv2.dat

  if [ "$1" != "no-shut-down" ]; then
      shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

# set the error handler for checking tpm2_getcap call
trap onerror ERR

# Check for encryptdecrypt command code 0x164
tpm2_getcap -c commands > commands.cap

# clear the handler for the grep check
trap - ERR

grep -q 0x164 commands.cap
if [ $? != 0 ];then
    echo "WARN: Command EncryptDecrypt is not supported by your device, skipping..."
    exit 0
fi

# Now set the trap handler for ERR since we're past the command code check
trap onerror ERR

echo "12345678" > secret.dat

tpm2_clear -Q

tpm2_createprimary -Q -a e -g sha1 -G rsa -o primary.ctx

tpm2_create -Q -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx

tpm2_load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -o decrypt.ctx

tpm2_encryptdecrypt -Q -c decrypt.ctx  -i secret.dat -o encrypt.out

tpm2_encryptdecrypt -Q -c decrypt.ctx -D -i encrypt.out -o decrypt.out

# Test using stdin/stdout
cat secret.dat | tpm2_encryptdecrypt -c decrypt.ctx | tpm2_encryptdecrypt -c decrypt.ctx -D > secret2.dat

# test using IVs
dd if=/dev/urandom of=iv.dat bs=16 count=1
cat secret.dat | tpm2_encryptdecrypt -c decrypt.ctx --iv iv.dat | tpm2_encryptdecrypt -c decrypt.ctx --iv iv.dat:iv2.dat -D > secret2.dat

cmp secret.dat secret2.dat

# Test using specified object modes

tpm2_create -Q -G aes128cbc -u key.pub -r key.priv -C primary.ctx

rm decrypt.ctx
tpm2_load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -o decrypt.ctx

# We need to perform cbc on blocksize of 16
echo -n "1234567812345678" > secret.dat

# specified mode
tpm2_encryptdecrypt -Q -c decrypt.ctx -G cbc -i secret.dat --iv=iv.dat  -o encrypt.out

# Unspecified mode (figure out via readpublic)
tpm2_encryptdecrypt -Q -D -c decrypt.ctx -i encrypt.out --iv iv.dat -o decrypt.out

cmp secret.dat decrypt.out

# Test that iv looping works
tpm2_encryptdecrypt -Q -c decrypt.ctx -G cbc -i secret.dat --iv=iv.dat:iv2.dat -o encrypt.out
tpm2_encryptdecrypt -Q -c decrypt.ctx -G cbc -i secret.dat --iv=iv2.dat -o encrypt2.out

tpm2_encryptdecrypt -Q -D -c decrypt.ctx -i encrypt.out --iv iv.dat -o decrypt.out
tpm2_encryptdecrypt -Q -D -c decrypt.ctx -i encrypt2.out --iv iv2.dat -o decrypt2.out

cmp secret.dat decrypt.out
cmp secret.dat decrypt2.out

# Negative that bad mode fails
trap - ERR

# mode CFB should fail, since the object was explicitly created with mode CBC
tpm2_encryptdecrypt -Q -c decrypt.ctx -G cfb -i secret.dat --iv=iv.dat  -o encrypt.out

exit 0
