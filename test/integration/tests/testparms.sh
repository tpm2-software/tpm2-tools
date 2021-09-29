# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

aesmodes="$(populate_algs "details['encrypting'] and details['symmetric']")"
hashalgs="$(populate_algs "details['hash'] and not details['method'] \
                                           and not details['signing'] \
                                           and not details['symmetric'] \
                                           and alg is not None")"
eccmethods="$(populate_algs "details['signing'] and not details['hash'] and \"ec\" in alg")"
rsamethods="$(populate_algs "details['signing'] and not details['hash'] and \"rsa\" in alg")"

# Test that common algorithms are supported
for i in "rsa" "xor" "hmac" "ecc" "keyedhash"; do
    tpm2 testparms "${i}"
done

# Test that RSA signing schemes are supported
for i in ${rsamethods}; do
    echo "tpm2 testparms rsa:${i}"
    tpm2 testparms "rsa:${i}"
done

# Test that ECC signing schemes are supported
for i in ${eccmethods}; do
    tpm2 testparms "ecc:${i}"
done

# Test that aes modes are supported
for i in ${aesmodes}; do
    tpm2 testparms "aes128${i}"
done

# Test that xor on hash algs is supported
for i in ${hashalgs}; do
    tpm2 testparms "xor:${i}"
done

# Test that hmac on hash algs is supported
for i in ${hashalgs}; do
    tpm2 testparms "hmac:${i}"
done

# Test that null algorithm raise an error (error from software stack)
if ! tpm2 testparms "null" 2>&1 1>/dev/null | \
    grep -q "Invalid or unsupported by the tool : null"; then
    echo "tpm2 testparms with 'null' algorithm didn't fail"
    exit 1
else
    true
fi

# Attempt to specify a suite that is not supported (error from TPM)
if ! tpm2 getcap ecc-curves | grep -q TPM2_ECC_NIST_P521; then
    if tpm2 testparms "ecc521:ecdsa:camellia" &>/dev/null; then
        echo "tpm2 testparms succeeded while it shouldn't or TPM failed"
        exit 1
    else
        true
    fi
fi
exit 0
