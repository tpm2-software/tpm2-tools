# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f  primary.ctx creation.data creation.digest creation.ticket rsa.pub \
    rsa.priv signature.bin attestation.bin sslpub.pem qual.dat sec_key.pub \
    sec_key.priv sec_key.ctx

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear -Q

tpm2_createprimary -C o -c primary.ctx --creation-data creation.data \
-d creation.digest -t creation.ticket -Q

tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx -c signing_key.ctx -Q

tpm2_readpublic -c signing_key.ctx -f pem -o sslpub.pem

tpm2_certifycreation -C signing_key.ctx -c primary.ctx -d creation.digest \
-t creation.ticket -g sha256 -o signature.bin --attestation attestation.bin \
-f plain -s rsassa

openssl dgst -verify sslpub.pem -keyform pem -sha256 -signature signature.bin \
attestation.bin

#
# Test with qualifier data
#
dd if=/dev/urandom of=qual.dat bs=1 count=32

tpm2_certifycreation -C signing_key.ctx -c primary.ctx -d creation.digest \
-t creation.ticket -g sha256 -o signature.bin --attestation attestation.bin \
-f plain -s rsassa -q qual.dat

openssl dgst -verify sslpub.pem -keyform pem -sha256 -signature signature.bin \
attestation.bin

#
# Test certification with non primary keys
#
tpm2_create -C primary.ctx -u sec_key.pub -r sec_key.priv -t creation.ticket \
-d creation.digest --creation-data creation.data -Q

tpm2_load -C primary.ctx -u sec_key.pub -r sec_key.priv -c sec_key.ctx -Q

tpm2_certifycreation -C signing_key.ctx -c sec_key.ctx -d creation.digest \
-t creation.ticket -g sha256 -o signature.bin --attestation attestation.bin \
-f plain -s rsassa

openssl dgst -verify sslpub.pem -keyform pem -sha256 -signature signature.bin \
attestation.bin

exit 0
