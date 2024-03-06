# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f primary.ctx certify.ctx certify.pub certify.priv certify.name \
    attest.out sig.out &>/dev/null

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}

verify_signature_with_ssl() {
# Verify the signatures with openssl
tpm2 readpublic -Q -c certify.ctx -f pem -o certify.pem
openssl dgst -verify certify.pem -keyform pem -sha256 \
    -signature sig.out attest.out
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c primary.ctx -p signedpass

tpm2 create -Q -g sha256 -G rsa:rsassa -u certify.pub -r certify.priv \
    -C primary.ctx -P signedpass -p certifypass

tpm2 load -Q -C primary.ctx -P signedpass -u certify.pub -r certify.priv \
    -n certify.name -c certify.ctx

tpm2 certify \
    -c primary.ctx -P signedpass \
    -C certify.ctx -p certifypass \
    -g sha256 -o attest.out -f plain -s sig.out  

verify_signature_with_ssl

tpm2 print -t TPMS_ATTEST attest.out

# Test with full options

tpm2 certify \
    --certifiedkey-context primary.ctx --certifiedkey-auth signedpass \
    --signingkey-context certify.ctx --signingkey-auth certifypass \
    --hash-algorithm sha256 --attestation attest.out \
    --format plain --signature sig.out

verify_signature_with_ssl

exit 0
