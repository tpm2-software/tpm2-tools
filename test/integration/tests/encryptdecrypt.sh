# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
  rm -f primary.ctx decrypt.ctx key.pub key.priv key.name decrypt.out \
  decrypt2.out encrypt.out encrypt2.out secret.dat secret2.dat \
  iv.dat iv2.dat key128.ctx plain.dec128.tpm plain.dec256.tpm plain.enc128.tpm \
  plain.enc256.tpm sym128.key key256.ctx plain.dec128.ssl plain.dec256.ssl \
  plain.enc128.ssl plain.enc256.ssl plain.txt sym256.key

  if [ "$1" != "no-shut-down" ]; then
      shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

if ! is_cmd_supported "EncryptDecrypt"; then
    echo "Command EncryptDecrypt is not supported by your device, skipping..."
    skip_test
fi

echo "12345678" > secret.dat

tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha1 -G rsa -c primary.ctx

tpm2 create -Q -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx

tpm2 load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c decrypt.ctx

tpm2 encryptdecrypt -Q -c decrypt.ctx -o encrypt.out secret.dat

tpm2 encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out encrypt.out

# Test using stdin/stdout
cat secret.dat | tpm2 encryptdecrypt -c decrypt.ctx | tpm2 encryptdecrypt \
-c decrypt.ctx -d > secret2.dat

# test using IVs
dd if=/dev/urandom of=iv.dat bs=16 count=1
cat secret.dat | tpm2 encryptdecrypt -c decrypt.ctx --iv iv.dat | \
tpm2 encryptdecrypt -c decrypt.ctx --iv iv.dat:iv2.dat -d > secret2.dat

cmp secret.dat secret2.dat

# Test using specified object modes

tpm2 create -Q -G aes128cbc -u key.pub -r key.priv -C primary.ctx

rm decrypt.ctx
tpm2 load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c decrypt.ctx

# We need to perform cbc on blocksize of 16
echo -n 1234567812345678 > secret.dat

# specified mode
tpm2 encryptdecrypt -Q -c decrypt.ctx -G cbc --iv=iv.dat -o encrypt.out \
secret.dat

# Unspecified mode (figure out via readpublic)
tpm2 encryptdecrypt -Q -d -c decrypt.ctx --iv iv.dat -o decrypt.out encrypt.out

cmp secret.dat decrypt.out

# Test that iv looping works
tpm2 encryptdecrypt -Q -c decrypt.ctx -G cbc --iv=iv.dat:iv2.dat \
-o encrypt.out secret.dat
tpm2 encryptdecrypt -Q -c decrypt.ctx -G cbc --iv=iv2.dat -o encrypt2.out \
secret.dat

tpm2 encryptdecrypt -Q -d -c decrypt.ctx --iv iv.dat -o decrypt.out encrypt.out
tpm2 encryptdecrypt -Q -d -c decrypt.ctx --iv iv2.dat -o decrypt2.out \
encrypt2.out

cmp secret.dat decrypt.out
cmp secret.dat decrypt2.out

# Test that input data sizes greater than TPM2_MAX_BUFFER or 1024 work
dd if=/dev/zero bs=1 count=2048 status=none of=secret2.dat
cat secret2.dat | tpm2 encryptdecrypt -Q -c decrypt.ctx -o encrypt.out
tpm2 encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out encrypt.out

cmp secret2.dat decrypt.out

# Test that last block in input data shorter than block length has pkcs7 padding
dd if=/dev/zero bs=1 count=2050 status=none of=secret2.dat
cat secret2.dat | tpm2 encryptdecrypt -Q -c decrypt.ctx -o encrypt.out -e
tpm2 encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out encrypt.out
## Last block is short 14 or hex 0E trailing bytes
echo 0e0e0e0e0e0e0e0e0e0e0e0e0e0e | xxd -r -p >> secret2.dat
cmp secret2.dat decrypt.out

# Test that pkcs7 padding is added as last block for block length aligned inputs
dd if=/dev/zero bs=1 count=2048 status=none of=secret2.dat
cat secret2.dat | tpm2 encryptdecrypt -Q -c decrypt.ctx -o encrypt.out -e
tpm2 encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out encrypt.out
## Last block is short 16 or hex 10 trailing bytes
echo 10101010101010101010101010101010 | xxd -r -p >> secret2.dat
cmp secret2.dat decrypt.out

# Test pkcs7 padding is stripped from input data is shorter than block length
dd if=/dev/zero bs=1 count=2050 status=none of=secret2.dat
cat secret2.dat | tpm2 encryptdecrypt -Q -c decrypt.ctx -o encrypt.out -e
tpm2 encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out -e encrypt.out
cmp secret2.dat decrypt.out

# Test pkcs7 padding is stripped after few blocks within the buffer.
dd if=/dev/zero bs=1 count=2114 status=none of=secret2.dat
cat secret2.dat | tpm2 encryptdecrypt -Q -c decrypt.ctx -o encrypt.out -e
tpm2 encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out -e encrypt.out
cmp secret2.dat decrypt.out

# Test that pkcs7 pad is stripped off last block for block length aligned inputs
dd if=/dev/zero bs=1 count=2048 status=none of=secret2.dat
cat secret2.dat | tpm2 encryptdecrypt -Q -c decrypt.ctx -o encrypt.out -e
tpm2 encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out -e encrypt.out
cmp secret2.dat decrypt.out

# Test pkcs7 padding larger than block size is ignored
dd if=/dev/zero bs=1 count=48 status=none of=secret2.dat
echo ffffffffffffffffffffffffffffffff | xxd -r -p >> secret2.dat
cat secret2.dat | tpm2 encryptdecrypt -Q -c decrypt.ctx -o encrypt.out
tpm2 encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out -e encrypt.out
cmp secret2.dat decrypt.out

# Test inconsistent pkcs7 padding is ignored
dd if=/dev/zero bs=1 count=48 status=none of=secret2.dat
echo 0102030405060708090a0b0c0d0e0f10 | xxd -r -p >> secret2.dat
cat secret2.dat | tpm2 encryptdecrypt -Q -c decrypt.ctx -o encrypt.out
tpm2 encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out -e encrypt.out
cmp secret2.dat decrypt.out

# Negative that bad mode fails
trap - ERR

# mode CFB should fail, since the object was explicitly created with mode CBC
tpm2 encryptdecrypt -Q -c decrypt.ctx -G cfb --iv=iv.dat -o encrypt.out \
secret.dat

# set the error handler for checking interoperability with openssl
trap onerror ERR

# Testing interoperability with openssl - Also exercises PKCS7 padding
dd if=/dev/urandom of=sym128.key bs=1 count=16
dd if=/dev/urandom of=sym256.key bs=1 count=32
tpm2 loadexternal -C n -G aes -r sym128.key -c key128.ctx
tpm2 loadexternal -C n -G aes -r sym256.key -c key256.ctx
echo "plaintext" > plain.txt

## Encrypt with ossl and tpm for cbc mode that requires padding

### Key size = 128
openssl enc -in plain.txt -out plain.enc128.ssl -K `xxd -c 128 -p sym128.key` \
-aes-128-cbc -iv 0

tpm2 encryptdecrypt -c key128.ctx -o plain.enc128.tpm -e -G cbc plain.txt

diff plain.enc128.ssl plain.enc128.tpm

### Key size = 256
openssl enc -in plain.txt -out plain.enc256.ssl -K `xxd -c 256 -p sym256.key` \
-aes-256-cbc -iv 0

tpm2 encryptdecrypt -c key256.ctx -o plain.enc256.tpm -e -G cbc plain.txt

diff plain.enc256.ssl plain.enc256.tpm

## Decrypt ciphertext from tpm in openssl and vice versa

### Key size = 128
tpm2 encryptdecrypt -c key128.ctx -o plain.dec128.tpm -e \
-G cbc -d plain.enc128.ssl

diff plain.dec128.tpm plain.txt

openssl enc -d -in plain.enc128.tpm -out plain.dec128.ssl -aes-128-cbc -iv 0 \
-K `xxd -c 128 -p sym128.key`

diff plain.dec128.ssl plain.txt

### Key size = 256
tpm2 encryptdecrypt -c key256.ctx -o plain.dec256.tpm -e \
-G cbc -d plain.enc256.ssl

diff plain.dec256.tpm plain.txt

openssl enc -d -in plain.enc256.tpm -out plain.dec256.ssl -aes-256-cbc -iv 0 \
-K `xxd -c 256 -p sym256.key`

diff plain.dec256.ssl plain.txt

## Encrypt with ossl and tpm for cfb mode that does not apply padding

### Key size = 128
openssl enc -in plain.txt -out plain.enc128.ssl -K `xxd -c 128 -p sym128.key` \
-aes-128-cfb -iv 0

tpm2 encryptdecrypt -c key128.ctx -o plain.enc128.tpm -G cfb plain.txt

diff plain.enc128.ssl plain.enc128.tpm

### Key size = 256
openssl enc -in plain.txt -out plain.enc256.ssl -K `xxd -c 256 -p sym256.key` \
-aes-256-cfb -iv 0

tpm2 encryptdecrypt -c key256.ctx -o plain.enc256.tpm -G cfb plain.txt

diff plain.enc256.ssl plain.enc256.tpm

## Decrypt ciphertext from tpm in openssl and vice versa

### Key size = 128
tpm2 encryptdecrypt -c key128.ctx -o plain.dec128.tpm \
-G cfb -d plain.enc128.ssl

diff plain.dec128.tpm plain.txt

openssl enc -d -in plain.enc128.tpm -out plain.dec128.ssl -aes-128-cfb -iv 0 \
-K `xxd -c 128 -p sym128.key`

diff plain.dec128.ssl plain.txt

### Key size = 256
tpm2 encryptdecrypt -c key256.ctx -o plain.dec256.tpm \
-G cfb -d plain.enc256.ssl

diff plain.dec256.tpm plain.txt

openssl enc -d -in plain.enc256.tpm -out plain.dec256.ssl -aes-256-cfb -iv 0 \
-K `xxd -c 256 -p sym256.key`

diff plain.dec256.ssl plain.txt

exit 0
