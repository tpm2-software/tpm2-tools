# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f primary.ctx new_parent.prv new_parent.pub new_parent.ctx policy.dat \
    session.dat key.prv key.pub key.ctx duppriv.bin dupseed.dat key2.prv \
    key2.pub key2.ctx sym_key_in.bin cleartext.txt secret.bin decrypted.txt \
    primary.pub rsa-priv.pem rsa.pub rsa.priv rsa.dpriv rsa.seed rsa-pub.pem rsa.sig

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

create_duplication_policy() {
    tpm2 startauthsession -Q -S session.dat
    tpm2 policycommandcode -Q -S session.dat -L policy.dat TPM2_CC_Duplicate
    tpm2 flushcontext -Q session.dat
    rm session.dat
}

start_duplication_session() {
    tpm2 startauthsession -Q --policy-session -S session.dat
    tpm2 policycommandcode -Q -S session.dat -L policy.dat TPM2_CC_Duplicate
}

end_duplication_session() {
    tpm2 flushcontext -Q session.dat
    rm session.dat
}

dump_duplication_session() {
    rm session.dat
}

dd if=/dev/urandom of=sym_key_in.bin bs=1 count=16 status=none

tpm2 createprimary -Q -C o -g sha256 -G rsa -c primary.ctx

# Create a new parent, we will only use the public portion
tpm2 create -Q -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
-u new_parent.pub -a "decrypt|fixedparent|fixedtpm|restricted|\
sensitivedataorigin"

# Create the key we want to duplicate
create_duplication_policy
tpm2 create -Q -C primary.ctx -g sha256 -G rsa -r key.prv -u key.pub \
-L policy.dat -a "sensitivedataorigin|sign|decrypt"
tpm2 load -Q -C primary.ctx -r key.prv -u key.pub -c key.ctx

tpm2 loadexternal -Q -C o -u new_parent.pub -c new_parent.ctx

## Null parent, Null Sym Alg
start_duplication_session
tpm2 duplicate -Q -C null -c key.ctx -G null -p "session:session.dat" \
-r dupprv.bin -s dupseed.dat
end_duplication_session

## Null Sym Alg
start_duplication_session
tpm2 duplicate -Q -C new_parent.ctx -c key.ctx -G null \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## Null parent
start_duplication_session
tpm2 duplicate -Q -C null -c key.ctx -G aes -i sym_key_in.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## AES Sym Alg, user supplied key
start_duplication_session
tpm2 duplicate -Q -C new_parent.ctx -c key.ctx -G aes -i sym_key_in.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## AES Sym Alg, no user supplied key
start_duplication_session
tpm2 duplicate -Q -C new_parent.ctx -c key.ctx -G aes -o sym_key_out.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## Repeat the tests with a key that requires encrypted duplication
tpm2 create -Q -C primary.ctx -g sha256 -G rsa -r key2.prv -u key2.pub \
-L policy.dat -a "sensitivedataorigin|sign|decrypt|encryptedduplication"
tpm2 load -Q -C primary.ctx -r key2.prv -u key2.pub -c key2.ctx

## AES Sym Alg, user supplied key
start_duplication_session
tpm2 duplicate -Q -C new_parent.ctx -c key2.ctx -G aes -i sym_key_in.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## AES Sym Alg, no user supplied key
start_duplication_session
tpm2 duplicate -Q -C new_parent.ctx -c key2.ctx -G aes -o sym_key_out.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
end_duplication_session

## External RSA key, wrapped for the primary key
tpm2 readpublic -c primary.ctx -o primary.pub
openssl genrsa -out rsa-priv.pem
openssl rsa -in rsa-priv.pem -pubout > rsa-pub.pem
tpm2 duplicate \
	--tcti none \
	-U primary.pub \
	-G rsa \
	-k rsa-priv.pem \
	-u rsa.pub \
	-r rsa.dpriv \
	-s rsa.seed
tpm2 import \
	-C primary.ctx \
	-G rsa \
	-i rsa.dpriv \
	-s rsa.seed \
	-u rsa.pub \
	-r rsa.priv

# validate that TPM signatures with this imported key are acceptable to OpenSSL
tpm2 load \
	-C primary.ctx \
	-c rsa.ctx \
	-u rsa.pub \
	-r rsa.priv
echo foo | tpm2 sign \
	-c rsa.ctx \
	-o rsa.sig \
	-f plain
echo foo | openssl dgst \
	-sha256 \
	-verify rsa-pub.pem \
	-signature rsa.sig

## External RSA key, with a password authorization policy
echo magicwords > cleartext.txt
openssl pkeyutl \
	-encrypt \
	-pubin \
	-inkey rsa-pub.pem \
	-in cleartext.txt \
	-out secret.bin

tpm2 startauthsession -S session.dat
tpm2 policypassword -S session.dat -L policy.dat

tpm2 duplicate \
	--tcti none \
	-U primary.pub \
	-G rsa \
	-k rsa-priv.pem \
	-u rsa.pub \
	-r rsa.dpriv \
	-s rsa.seed \
	-L policy.dat \
	-p secretpassword

tpm2 import \
	-C primary.ctx \
	-G rsa \
	-i rsa.dpriv \
	-s rsa.seed \
	-u rsa.pub \
	-r rsa.priv

# validate that TPM can decrypt messages with this imported key

tpm2 load \
	-C primary.ctx \
	-c rsa.ctx \
	-u rsa.pub \
	-r rsa.priv \

tpm2 startauthsession -S session.dat --policy-session
tpm2 policypassword -S session.dat -L policy.dat

cat secret.bin | tpm2 rsadecrypt \
	-c rsa.ctx \
	-p session:session.dat+secretpassword \
	> decrypted.txt
cmp cleartext.txt decrypted.txt

trap - ERR

## Attempt to decrypt without the password or policy

cat secret.bin | tpm2 rsadecrypt \
	-c rsa.ctx \
	-p session:session.dat
if [ $? -eq 0 ]; then
  echo "Expected \"tpm2 rsadecrypt\" to fail without password."
  exit 1
fi
cat secret.bin | tpm2 rsadecrypt \
	-c rsa.ctx
if [ $? -eq 0 ]; then
  echo "Expected \"tpm2 rsadecrypt\" to fail without policy."
  exit 1
fi

## Null parent - should fail (TPM_RC_HIERARCHY)
start_duplication_session
tpm2 duplicate -Q -C null -c key2.ctx -G aes -i sym_key_in.bin \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
if [ $? -eq 0 ]; then
  echo "Expected \"tpm2 duplicate -C null \" to fail."
  exit 1
fi
dump_duplication_session

## Null Sym Alg - should fail (TPM_RC_SYMMETRIC)
start_duplication_session
tpm2 duplicate -Q -C new_parent.ctx -c key2.ctx -G null \
-p "session:session.dat" -r dupprv.bin -s dupseed.dat
if [ $? -eq 0 ]; then
  echo "Expected \"tpm2 duplicate -G null \" to fail."
  exit 1
fi
dump_duplication_session

exit 0
