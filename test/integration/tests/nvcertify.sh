# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f  primary.ctx signing_key.pub signing_key.priv signature.bin attestation.bin \
    sslpub.pem signing_key.ctx

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear -Q

tpm2_createprimary -C o -c primary.ctx -Q

tpm2_create -G rsa -u signing_key.pub -r signing_key.priv -C primary.ctx \
-c signing_key.ctx -Q

tpm2_readpublic -c signing_key.ctx -f pem -o sslpub.pem -Q

tpm2_nvdefine -s 32 -a "authread|authwrite" 1

dd if=/dev/urandom bs=1 count=32 status=none| tpm2_nvwrite 1 -i-

tpm2_nvcertify -C signing_key.ctx -g sha256 -f plain -s rsassa \
-o signature.bin --attestation attestation.bin --size 32 1

dd if=attestation.bin bs=1 skip=2 | \
openssl dgst -verify sslpub.pem -keyform pem -sha256 -signature signature.bin

exit 0
