# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

# We don't need a TPM for this test, so unset the EXIT handler.
trap - EXIT

outfile="test.cert"
daysvalid=10
fail=0

# Generate a new cert and parse it with openssl
tpm2 certifyX509certutil -o $outfile -d $daysvalid
openssl asn1parse -in $outfile -inform DER
if [ $? -ne 0 ]; then
    rm $outfile
	exit 1
fi
rm $outfile

# Use valid issuer and subjec options
tpm2 certifyX509certutil -o $outfile -d $daysvalid -i "C=US;CN=cname;O=My Org;OU=Org Unit" -s "C=US;CN=cname;O=Sub Org;OU=Org Unit"
openssl asn1parse -in $outfile -inform DER | grep "cname"
if [ $? -ne 0 ]; then
    rm $outfile
	exit 1
fi
rm $outfile

# Use invalid issuer and subjec options - defaults should be used
tpm2 certifyX509certutil -o $outfile -i "C=USA;CN=12345678901234567890;O=12345678901234567890;OU=12345678901234567890" -s "C=USA;CN=12345678901234567890;O=1234567890;OU=1234567890"
openssl asn1parse -in $outfile -inform DER | grep "CA Org"
if [ $? -ne 0 ]; then
    rm $outfile
	exit 1
fi
rm $outfile

# Use unsupported fields for issuer and subjec options - defaults should be used
tpm2 certifyX509certutil -o $outfile -i "B=USA;CN=12345678901234567890;X=12345678901234567890;YXZ=12345678901234567890;O=XXXXXXXX;CN=1234567890;" -s "ABC=USA;CNN=12345678901234567890;CCCCCC=1234567890;@#$=1234567890;O=XXXXXXXX;CN=1234567890;"
openssl asn1parse -in $outfile -inform DER | grep "default"
if [ $? -ne 0 ]; then
   # rm $outfile
	exit 1
fi
rm $outfile

# Negative tests
# generate cert in non-existing path
if tpm2 certifyX509certutil -o /non/existing/path/$outfile &>/dev/null; then
    echo "Expected \"$cmd\" to fail."
    exit 1
else
    true
fi

# Use only invalid fields for issuer - should fail
if tpm2 certifyX509certutil -i "B=USA;Y=12345678901234567890;X=12345678901234567890;YXZ=12345678901234567890" &> /dev/null; then
    echo "Expected \"$cmd\" to fail."
    exit 1
else
    true
fi

exit "$fail"
