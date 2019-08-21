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
    tpm2_testparms "${i}"
done

# Test that RSA signing schemes are supported
for i in ${rsamethods}; do
    echo "tpm2_testparms rsa:${i}"
    tpm2_testparms "rsa:${i}"
done

# Test that ECC signing schemes are supported
for i in ${eccmethods}; do
    tpm2_testparms "ecc:${i}"
done

# Test that aes modes are supported
for i in ${aesmodes}; do
    tpm2_testparms "aes128${i}"
done

# Test that xor on hash algs is supported
for i in ${hashalgs}; do
    tpm2_testparms "xor:${i}"
done

# Test that hmac on hash algs is supported
for i in ${hashalgs}; do
    tpm2_testparms "hmac:${i}"
done

# Test that null algorithm raise an error (error from software stack)
if ! tpm2_testparms "null" 2>&1 1>/dev/null | \
    grep -q "Invalid or unsupported by the tool : null"; then
    echo "tpm2_testparms with 'null' algorithm didn't fail"
    exit 1
else
    true
fi

# Attempt to specify a suite that is not supported (error from TPM)
if tpm2_testparms "ecc521:ecdsa:aes256cbc" &>/dev/null; then
    echo "tpm2_testparms succeeded while it shouldn't or TPM failed"
    exit 1
else
    true
fi
exit 0
