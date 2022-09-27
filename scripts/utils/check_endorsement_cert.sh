#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause

TESTDIR=$(mktemp -d || exit 1)
cleanup() {
    rm -rf $TESTDIR
}
trap cleanup EXIT

EKPUB=$1
EKCERT=$2

usage() {
cat <<EOF

This utility checks the endorsement key and it's certificate for the following:
1. Downloads intermediate and root certificate using authority information
   access from the endorsement-key-certificate.
2. Endorsement-key-public match with the endorsement-key-certificate.
3. Subject and issuer hashes of certficates in the chain.
4. Validation of the certificate chain.

This utility assumes a typical cert chain: Root->Intermediate->Entity.

Requirements:
1. The ek-public and ek-certificate specified - in that order
2. The ekpublic be specified in TPM2B_PUBLIC format and the endorsement
   certificate in PEM format.

Usage: $0 [options] FILE FILE
Options:
  -h    print this help text.
EOF
  exit 0
}

while getopts ":h" opt; do
  case $opt in
    h)
      usage
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

if [ "$#" -ne 2 ]; then
    (>&2 echo "Error: expected ek-public and ek-certificate - in that order")
    exit 1
fi

# echo "Extracting public key from ek certificate"
openssl x509 -pubkey -in $EKCERT -nocert > $TESTDIR/pub_in_cert.pem
if [ $? != 0 ];then
    echo "Invalid endorsement certificate - Expected in PEM format"
    exit 1
fi
# echo "Coverting ekpub from TPM2B_PUBLIC to pem"
tpm2_print -t TPM2B_PUBLIC -f pem $EKPUB > $TESTDIR/ekpub.pem -Q 
if [ $? != 0 ];then
    echo "Invalid endorsement key public - Expected EK in TPM2B_PUBLIC format"
    exit 1
fi
# echo "Checking if the EKpublic matches the one in the certificate"
cmp -s $TESTDIR/pub_in_cert.pem $TESTDIR/ekpub.pem
if [ $? != 0 ];then
    echo "Mismatch - The endorsement key doesn't match the one in the cert"
    exit 1
fi

# echo "Retrieving intermediate certificate"
intermediate_cert_link=$(openssl x509 -in $EKCERT -noout -text | \
                         grep -A1 "Authority Information Access" | \
                         awk -F URI: '{print $2}')
if [ $? != 0 ];then
    echo "Could not parse intermediate certificate information"
    exit 1
fi
wget -q $intermediate_cert_link -O $TESTDIR/intermediate.crt
if [ $? != 0 ];then
    echo "Could not retrieve intermediate certificate"
    exit 1
fi
openssl x509 -in $TESTDIR/intermediate.crt -inform DER -outform PEM \
    -out $TESTDIR/intermediate.pem

# echo "Retrieving root certificate"
root_cert_link=$(openssl x509 -in $TESTDIR/intermediate.pem -noout -text | \
                         grep -A1 "Authority Information Access" | \
                         awk -F URI: '{print $2}')
if [ $? != 0 ];then
    echo "Could not parse root certificate information"
    exit 1
fi
wget -q $root_cert_link -O $TESTDIR/root.crt
if [ $? != 0 ];then
    echo "Could not retrieve root certificate"
    exit 1
fi
openssl x509 -in $TESTDIR/root.crt -inform DER -outform PEM \
    -out $TESTDIR/root.pem

# echo "Test subject and issuers"
EKCERT_HASH=$(openssl x509 -in $EKCERT -issuer_hash -noout)
INTERMEDIATE_EKCERT_HASH=$(openssl x509 -in $TESTDIR/intermediate.pem -hash -noout)
if [ $EKCERT_HASH != $INTERMEDIATE_EKCERT_HASH ];then
    echo "EKcert issuer-hash does not match Intermediate subject-hash"
    exit 1
fi

INTERMEDIATE_HASH=$(openssl x509 -in $TESTDIR/intermediate.pem -issuer_hash -noout)
ROOT_INTERMEDIATE_HASH=$(openssl x509 -in $TESTDIR/root.pem -hash -noout)
if [ $INTERMEDIATE_HASH != $ROOT_INTERMEDIATE_HASH ];then
    echo "Intermediate issuer-hash does not match Root subject-hash"
    exit 1
fi

# echo "Testing the certificate chain"
openssl verify \
    -CAfile $TESTDIR/root.pem \
    -untrusted $TESTDIR/intermediate.pem \
    $EKCERT
if [ $? != 0 ];then
    echo "Failed $EKCERT certificate validation"
    exit 1
fi

exit 0
