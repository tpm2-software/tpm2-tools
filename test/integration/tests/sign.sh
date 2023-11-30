# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

file_primary_key_ctx=context.p_B1
file_signing_key_pub=opuB1_B8
file_signing_key_priv=oprB1_B8
file_signing_key_ctx=context_load_out_B1_B8
file_signing_key_name=name.load.B1_B8
file_signing_key_pub_pem=oppB1_B8
file_input_data=secret.data
file_input_digest=secret.digest
file_output_data=sig.4
file_output_ticket=secret.ticket
file_output_hash=secret.hash
rsa_key_type=rsa2048
ecc_key_type=ecc256

handle_signing_key=0x81010005

alg_hash=sha256
alg_primary_key=rsa

cleanup() {
    rm -f $file_input_data $file_primary_key_ctx $file_signing_key_pub \
          $file_signing_key_priv $file_signing_key_ctx $file_signing_key_name \
          $file_output_data $file_input_digest $file_output_ticket \
          $file_output_hash $file_signing_key_pub_pem

    tpm2 evictcontrol -Q -Co -c $handle_signing_key 2>/dev/null || true

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

test_symmetric() {
    local alg_signing_key=$1

    echo "12345678" > $file_input_data

    tpm2 clear

    tpm2 createprimary -Q -C e -g $alg_hash -G $alg_primary_key \
    -c $file_primary_key_ctx

    tpm2 create -Q -g $alg_hash -G $alg_signing_key -u $file_signing_key_pub \
    -r $file_signing_key_priv -C $file_primary_key_ctx

    tpm2 load -Q -C $file_primary_key_ctx -u $file_signing_key_pub \
    -r $file_signing_key_priv -n $file_signing_key_name -c $file_signing_key_ctx

    tpm2 sign -Q -c $file_signing_key_ctx -g $alg_hash \
    -o $file_output_data $file_input_data

    rm -f $file_output_data

    tpm2 evictcontrol -Q -C o -c $file_signing_key_ctx $handle_signing_key

    tpm2 sign -Q -c $handle_signing_key -g $alg_hash -o $file_output_data \
    $file_input_data

    rm -f $file_output_data

    # generate hash and test validation

    tpm2 hash -Q -C e -g $alg_hash -o $file_output_hash -t $file_output_ticket \
    $file_input_data

    tpm2 sign -Q -c $handle_signing_key -g $alg_hash -o $file_output_data \
    -t $file_output_ticket $file_input_data

    rm -f $file_output_data

    # test with digest, no validation

    shasum -a 256 $file_input_data | awk '{ print "000000 " $1 }' | xxd -r -c 32 > \
    $file_input_digest

    tpm2 sign -Q -c $handle_signing_key -g $alg_hash -d -o $file_output_data \
    $file_input_digest

    rm -f $file_output_data
}

create_signature() {
    local sign_scheme=$1
    if [ "$sign_scheme" = "" ]; then
        tpm2 sign -Q -c $file_signing_key_ctx -g $alg_hash -f plain \
        -o $file_output_data $file_input_data
    else
        tpm2 sign -Q -c $file_signing_key_ctx -g $alg_hash -s $sign_scheme \
        -f plain -o $file_output_data $file_input_data
    fi
}

get_openssl_version_number() {
    # Ubuntu 14.04, 16.04, 18.04 and 19.04:
    # "OpenSSL 1.0.1f 6 Jan 2014"
    # "OpenSSL 1.0.2g  1 Mar 2016"
    # "OpenSSL 1.1.0g  2 Nov 2017"
    # "OpenSSL 1.1.1b  26 Feb 2019"
    if [ -z "$1" ]; then
        local openssl_version=$(openssl version -v)
    else
        local openssl_version="$1"
    fi
    local openssl_version_parsed=$(echo "$openssl_version" | sed -r 's/^OpenSSL ([0-9]+)\.([0-9]+)\.([0-9]+).*$/\1 \2 \3/')
    local openssl_v1=$(echo $openssl_version_parsed | cut -d ' ' -f 1)
    local openssl_v2=$(echo $openssl_version_parsed | cut -d ' ' -f 2)
    local openssl_v3=$(echo $openssl_version_parsed | cut -d ' ' -f 3)
    local openssl_version_num=$(("$openssl_v1"<<16 + "$openssl_v2"<<8 + "$openssl_v3"))
    echo "$openssl_version_num"
}

verify_signature() {
    local sign_scheme=$1

    if [ "$sign_scheme" = "rsapss" ] ; then
        # Explanation:

        # RSA-PSS has a parameter called salt length.
        # You need to know what value of salt length was used to create the
        # signature in order to verify the signature.
        # OpenSSL can actually automatically determine the correct value, so
        # strictly speaking we could just let it and simplify this test a lot.
        # But, if you want to verify the signature using some other API,
        # you might need to know the salt length used by the TPM to produce the
        # signature.
        # It can be either "digest" or "max". You can use openssl the check
        # whether it's "digest", and if it's not then it's "max".

        # From TCG TPM 2.0, Part 1: Architecture, Appendix B.7
        # "... the random salt length will be the largest size allowed by the
        #  key size and message digest size."

        # From NIST FIPS PUB 186-4, Section 5.5
        # "... the length (in bytes) of the salt (sLen) shall satisfy
        #  0 <= sLen <= hLen, where hLen is the length of the hash function
        #  output block (in bytes)."

        # From TCG FIPS 140-2 Guidance for TPM 2.0, Section 5.2.1.3
        # "If the TPM implementation is required to be compliant with FIPS 186-4,
        #  then the random salt length will be the largest size allowed by that
        #  specification."

        # Thus, if the TPM is in "FIPS mode", PSS salt length is "digest",
        #  otherwise PSS salt length is "max".
        # Either one is accepted by this test.
        # The IBM TPM software emulator (at least the version in ibmtpm1332.tar.gz)
        #  uses "digest".

        local openssl_current_version_num=$(get_openssl_version_number)
        local openssl_1_1_1_version_num=$(get_openssl_version_number "OpenSSL 1.1.1")

        # Explanation:
        # In version 1.1.1, openssl switched from "-1","-2" (meaning "digest" and
        # "auto" correspondingly) to "digest", "max" and "auto".
        # See section "rsa_pss_saltlen:len" in
        # https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/doc/man1/pkeyutl.pod
        # and same section in
        # https://github.com/openssl/openssl/blob/OpenSSL_1_1_0-stable/doc/apps/pkeyutl.pod
        if [ "$openssl_current_version_num" -ge "$openssl_1_1_1_version_num" ] ; then
            local pss_salt_len_arg_digest="digest"
            local pss_salt_len_arg_max="max"
            local pss_salt_len_arg_auto="auto"
        else
            local pss_salt_len_arg_digest="-1"
            local pss_salt_len_arg_auto="-2"
        fi

        openssl pkeyutl -verify \
            -in $file_input_digest \
            -sigfile $file_output_data \
            -pubin \
            -inkey $file_signing_key_pub_pem \
            -keyform pem \
            -pkeyopt digest:$alg_hash \
            -pkeyopt rsa_padding_mode:pss \
            -pkeyopt rsa_pss_saltlen:$pss_salt_len_arg_digest \
            |& grep -q '^Signature Verified Successfully' \
        || \
        openssl pkeyutl -verify \
            -in $file_input_digest \
            -sigfile $file_output_data \
            -pubin \
            -inkey $file_signing_key_pub_pem \
            -keyform pem \
            -pkeyopt digest:$alg_hash \
            -pkeyopt rsa_padding_mode:pss \
            -pkeyopt rsa_pss_saltlen:$pss_salt_len_arg_auto \
            |& grep -q '^Signature Verified Successfully'
    else
        openssl pkeyutl -verify \
            -in $file_input_digest \
            -sigfile $file_output_data \
            -pubin \
            -inkey $file_signing_key_pub_pem \
            -keyform pem \
            -pkeyopt digest:$alg_hash \
            |& grep -q '^Signature Verified Successfully'
    fi
}

test_asymmetric() {
    local alg_signing_key=$1

    head -c30 /dev/urandom > $file_input_data

    shasum -a 256 $file_input_data | awk '{ print "000000 " $1 }' | \
    xxd -r -c 32 > $file_input_digest

    tpm2 clear

    tpm2 createprimary -Q -C e -g $alg_hash -G $alg_primary_key \
    -c $file_primary_key_ctx

    tpm2 create -Q -g $alg_hash -G $alg_signing_key -u $file_signing_key_pub \
    -r $file_signing_key_priv -C $file_primary_key_ctx

    tpm2 load -Q -C $file_primary_key_ctx -u $file_signing_key_pub \
    -r $file_signing_key_priv -n $file_signing_key_name -c $file_signing_key_ctx

    tpm2 readpublic -Q -c $file_signing_key_ctx --format=pem \
    -o $file_signing_key_pub_pem

    local sign_scheme

    if [ "$alg_signing_key" = "$rsa_key_type" ] ; then
        for sign_scheme in "" "rsassa" "rsapss"
        do
            create_signature $sign_scheme
            verify_signature $sign_scheme

            rm -f $file_output_data
        done
    fi

    if [ "$alg_signing_key" = "$ecc_key_type" ]; then
        for sign_scheme in "" "ecdsa"
        do
            create_signature $sign_scheme
            verify_signature $sign_scheme

            rm -f $file_output_data
        done
    fi
}

start_up

cleanup "no-shut-down"

# make sure commands failing inside the function will cause the script to fail!
(
    set -e
    test_symmetric "hmac"
    cleanup "no-shut-down"
)

for key_type in $rsa_key_type $ecc_key_type
do
    # make sure commands failing inside the function will cause the script
    # to fail!
    (
        set -e
        test_asymmetric $key_type
        cleanup "no-shut-down"
    )
done

# Test signing with ecdaa scheme
head -c30 /dev/urandom | openssl dgst -sha256 -binary > test.rnd
tpm2 clear
tpm2 createprimary -Q -C o -c prim.ctx -g sha256 -G rsa
tpm2 create -Q -g sha256 -G ecc256:ecdaa -u key.pub -r key.priv -C prim.ctx
tpm2 load -C prim.ctx -u key.pub -r key.priv -n key.name -c key.ctx
tpm2 readpublic -c key.ctx --format=pem -o key.pem
tpm2 commit -c key.ctx -t commit.ctr --eccpoint-K K.bin --eccpoint-L L.bin -u E.bin
tpm2 commit -c key.ctx -t commit.ctr --eccpoint-K K.bin --eccpoint-L L.bin -u E.bin
tpm2 sign -c key.ctx -g sha256 -o test.sig test.rnd -s ecdaa --commit-index 1
tpm2 sign -c key.ctx -g sha256 -o test.sig test.rnd -s ecdaa

# Test that invalid password returns the proper code
cleanup "no-shut-down"

echo "12345678" > $file_input_data

tpm2 createprimary -Q -c $file_primary_key_ctx
tpm2 create -Q -C $file_primary_key_ctx -u $file_signing_key_pub \
-r $file_signing_key_priv -p "mypassword"
tpm2 load -Q -C $file_primary_key_ctx -u $file_signing_key_pub \
-r $file_signing_key_priv -n $file_signing_key_name -c $file_signing_key_ctx

# Negative test, remove error handler
trap - ERR

tpm2 sign -Q -p "badpassword" -c $file_signing_key_ctx -g $alg_hash \
-o $file_output_data $file_input_data
if [ $? != 3 ]; then
    echo "Expected RC 3, got: $?" 1>&2
fi
trap onerror ERR

exit 0
