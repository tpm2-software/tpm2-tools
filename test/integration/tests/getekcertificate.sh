# SPDX-License-Identifier: BSD-3-Clause

if [ `uname` == "FreeBSD" ]; then
        exit 77
fi

source helpers.sh

cleanup() {
    rm -f test_rsa_ek.pub rsa_ek_cert.bin stdout_rsa_ek_cert.bin \
          test_ecc_ek.pub ecc_ek_cert.bin stdout_ecc_ek_cert.bin

    shut_down
}
trap cleanup EXIT

start_up

# Check connectivity
if [ -z "$(curl -V 2>/dev/null)" ]; then
    echo "curl is not not installed. Skipping connection check."
    exit 077
else
    if [ "$(curl --silent --output /dev/null --write-out %{http_code} \
    'https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D')" != '200' ]; then
        echo 'No connection to https://ekop.intel.com/'
        exit 77
    fi
fi

# Setup retries for when EK certificate cannot be retrieved on first try
getekcert_with_retries() {
    trap - ERR
    INTL_URL=https://ekop.intel.com/ekcertservice/
    cert_done=
    for i in 1 2 3;
        do
        tpm2 getekcertificate -u $1 -x -X -o $2 $INTL_URL
        tpm2 getekcertificate -u $1 -x -X $INTL_URL > $3
        # Test that stdout output is the same as output to file
        cmp $2 $3
        if [ $? == 0 ]; then
            cert_done=1
            break
        fi
    done
    trap onerror ERR
    test $cert_done
}

# Sample RSA ek public from a real platform
echo "013a0001000b000300b20020837197674484b3f81a90cc8d46a5d724fd52
d76e06520b64f2a1da1b331469aa00060080004300100800000000000100
c320e2f244a8601aacf3e01d26c665249935562de1da197e9e7f076c4696
13cfb653e98ec2c386fc1d133f2c8c6cc338b732f0b208bd838a877a3e5b
bc3e1d4084e835c7c8906a1c05b4d2d30fdbebc1dbad950fa6b165bd4b6a
864603146164c0c4f59d489011ef1f928deea6e90061f3d375e564627315
1ef622252098be1a4ab01dc0a12227c609fdaceb115af408d4693a6f4991
9774695b0c12bc18a1ff7120a7337b2fb5f1951d8bb7f094d5b554c11c95
23b30729fe64787d0a13b9e630488dab4dfd86634a5270ec72fcc5a44dc6
79a8f32938dd8197e29dae839f5b4ca0f5de27c9522c23c54e1c2ce57859
525118bd4470b18180eef78ae4267bcd" | xxd -r -p > test_rsa_ek.pub

#
# RSA EK Certificate from ekop.intel.com
#
getekcert_with_retries test_rsa_ek.pub rsa_ek_cert.bin stdout_rsa_ek_cert.bin

# Retrieved certificate should be valid
tpm2 loadexternal -C e  -u test_rsa_ek.pub -c rsa_key.ctx
tpm2 readpublic -c rsa_key.ctx -f pem -o test_rsa_ek.pem
openssl x509 -pubkey -in rsa_ek_cert.bin -noout -out test_ek.pem
diff test_rsa_ek.pem test_ek.pem

# Sample ECC ek public from a real platform
echo "007a0023000b000300b20020837197674484b3f81a90cc8d46a5d724fd52
d76e06520b64f2a1da1b331469aa00060080004300100003001000206d8e
7630ee5d11e566e80299bfb9e43cec8c44f70bc8ad81b50f690a3deb7498
002021a536c8fef7482313d7f4517f11c9f2b4cd424cbc8fe9094b895668
51fe0853" | xxd -r -p > test_ecc_ek.pub

#
# ECC EK Certificate from ekop.intel.com
#
getekcert_with_retries test_ecc_ek.pub ecc_ek_cert.bin stdout_ecc_ek_cert.bin


# Retrieved certificate should be valid
tpm2 loadexternal -C e  -u test_ecc_ek.pub -c ecc_key.ctx
tpm2 readpublic -c ecc_key.ctx -f pem -o test_ecc_ek.pem
openssl x509 -pubkey -in ecc_ek_cert.bin -noout -out test_ek.pem
diff test_ecc_ek.pem test_ek.pem

# Retrieve EK certificates from NV indices
RSA_EK_CERT_NV_INDEX=0x01C00002
ECC_EK_CERT_NV_INDEX=0x01C0000A

define_ek_cert_nv_index() {
    file_size=`ls -l $1 | awk {'print $5'}`

    tpm2 nvdefine $2 -C p -s $file_size \
    -a 'ppwrite|ppread|ownerread|authread|no_da|platformcreate'

    tpm2 nvwrite -C p -i $1 $2
}

## ECC only INTC certificate from NV index
openssl x509 -in ecc_ek_cert.bin -out ecc_ek_cert.der -outform DER

define_ek_cert_nv_index ecc_ek_cert.der $ECC_EK_CERT_NV_INDEX

tpm2 getekcertificate -o nv_ecc_ek_cert.der

diff nv_ecc_ek_cert.der ecc_ek_cert.der

## RSA only INTC certificate from NV index
tpm2 nvundefine -C p $ECC_EK_CERT_NV_INDEX

openssl x509 -in rsa_ek_cert.bin -out rsa_ek_cert.der -outform DER

define_ek_cert_nv_index rsa_ek_cert.der $RSA_EK_CERT_NV_INDEX

tpm2 getekcertificate -o nv_rsa_ek_cert.der

diff nv_rsa_ek_cert.der rsa_ek_cert.der

rm nv_rsa_ek_cert.der nv_ecc_ek_cert.der -f

## RSA & ECC INTC certificates from NV index
define_ek_cert_nv_index ecc_ek_cert.der $ECC_EK_CERT_NV_INDEX

tpm2 getekcertificate -o nv_rsa_ek_cert.der -o nv_ecc_ek_cert.der

diff nv_rsa_ek_cert.der rsa_ek_cert.der
diff nv_ecc_ek_cert.der ecc_ek_cert.der

exit 0
