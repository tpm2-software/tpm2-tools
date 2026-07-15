# SPDX-License-Identifier: BSD-3-Clause
#!/usr/bin/env bash 

source helpers.sh

cleanup() {

    rm -f *.ctx
    rm -f child.*
    rm -f signature.bin attestation.bin
    shut_down
}
trap cleanup EXIT

start_up

test_nvcertify(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear
	tpm2 nvdefine -C o -s 64 -a "authread|authwrite|ownerwrite|ownerread" 1
	dd if=/dev/urandom bs=1 count=64 status=none | \
	tpm2 nvwrite 1 -i-
	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -u child.pub -r child.priv -R
	tpm2 load -C signkey.ctx -u child.pub -r child.priv -c child.ctx -R
	tpm2 nvcertify -C child.ctx -g "$2" -f plain -s mldsa -o signature.bin --attestation attestation.bin --size 0 1 

}

test_nvcertify mldsa44 sha256
test_nvcertify mldsa65 sha256
test_nvcertify mldsa44 sha512
test_nvcertify mldsa65 sha512 

exit 0
