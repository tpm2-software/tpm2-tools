# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

    rm -f primary.ctx
    rm -f mldsa.pub mldsa.priv mldsa.ctx
    rm -f mldsa2.pub mldsa2.priv mldsa2.ctx
    rm -f badkey.pub badkey.priv badkey.ctx
    rm -f msg.dat msg2.dat
    rm -f digest.bin digest2.bin digest_bad.bin
    rm -f sig.bin sig2.bin
    rm -f validation.tkt
}
trap cleanup EXIT

start_up

keyauth=keypass

test_signdigest(){
	alg="$1"
	alg2="$2"

	tpm2 clear
	#Create a primary parent
	tpm2 createprimary -C o -g "$alg2" -G rsa -c primary.ctx 

	# Create and load an MLDSA key
	tpm2 create -C primary.ctx -G "$alg" -u mldsa.pub -r mldsa.priv -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -R
	tpm2 load -C primary.ctx -u mldsa.pub -r mldsa.priv -c mldsa.ctx -R

	# Prepare test data
	echo -n "This is a test message for verifydigestsignature with MLDSA" > msg.dat
	echo -n "This is another message for verifydigestsignature with MLDSA" > msg2.dat

	# Compute digests externally
	openssl dgst -sha512 -binary -out digest.bin msg.dat
	openssl dgst -sha512 -binary -out digest2.bin msg2.dat


	# Generate a valid digest signature first
	tpm2 signdigest -c mldsa.ctx -o sig.bin -d digest.bin 
	test -s sig.bin


	# TPM verifydigestsignature
	tpm2 verifydigestsignature -c mldsa.ctx -s sig.bin -d digest.bin -t validation.tkt
	test -s validation.tkt
}

test_signdigest mldsa44 sha256
test_signdigest mldsa65 sha256
test_signdigest mldsa44 sha512
test_signdigest mldsa65 sha512

exit 0
