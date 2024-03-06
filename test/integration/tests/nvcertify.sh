# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f  primary.ctx signing_key.pub signing_key.priv signature.bin attestation.bin \
    sslpub.pem signing_key.ctx qual.dat

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear -Q

tpm2 createprimary -C o -c primary.ctx -Q

tpm2 create -G rsa -u signing_key.pub -r signing_key.priv -C primary.ctx \
-c signing_key.ctx -Q

tpm2 readpublic -c signing_key.ctx -f pem -o sslpub.pem -Q

tpm2 nvdefine -s 32 -a "authread|authwrite" 1

dd if=/dev/urandom bs=1 count=32 status=none| tpm2 nvwrite 1 -i-

tpm2 nvcertify -C signing_key.ctx -g sha256 -f plain -s rsassa \
-o signature.bin --attestation attestation.bin --size 32 1

openssl dgst -verify sslpub.pem -keyform pem -sha256 -signature signature.bin \
attestation.bin

#
# Test with qualifier data
#
dd if=/dev/urandom of=qual.dat bs=1 count=32

tpm2 nvcertify -C signing_key.ctx -g sha256 -f plain -s rsassa \
-o signature.bin --attestation attestation.bin --size 32 -q qual.dat 1

tpm2 print -t TPMS_ATTEST attestation.bin

openssl dgst -verify sslpub.pem -keyform pem -sha256 -signature signature.bin \
attestation.bin

#
# Test if qualifier data was present in the attestation
#
xxd -p attestation.bin | tr -d '\n' | grep `xxd -p qual.dat | tr -d '\n'`

exit 0
