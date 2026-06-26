# SPDX-License-Identifier: BSD-3-Clause
#!/usr/bin/env bash 

source helpers.sh

cleanup() {

    rm -f signkey.ctx
    rm -f mldsa.pub mldsa.priv mldsa.ctx
    rm -f signature.bin msg.bin
    rm -f verified.ticket
    rm -f signpub.out
    rm -f verifypub.ctx
    rm -f signkey.ctx
}
trap cleanup EXIT

start_up
tpm2 clear 
test_pqc_sign(){
	alg="$1"
	alg2="$2"
	echo -n "This is a test message for verifysequence with MLDSA" > msg.bin
	
	tpm2 createprimary -C o -G "$1" -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign'
	tpm2 signsequence -c signkey.ctx -i msg.bin -s signature.bin
	tpm2 readpublic -c signkey.ctx -o signpub.out
	tpm2 clear

	tpm2 loadexternal -u signpub.out -c verifypub.ctx
	tpm2 verifysequence -c verifypub.ctx -i msg.bin -s signature.bin -t verified.ticket
	tpm2 flushcontext -t
}

test_pqc_sign mldsa44 sha256
test_pqc_sign mldsa65 sha256
test_pqc_sign mldsa44 sha512
test_pqc_sign mldsa65 sha512


exit 0
