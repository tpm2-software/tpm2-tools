# SPDX-License-Identifier: BSD-3-Clause
#!/usr/bin/env bash 

source helpers.sh

cleanup() {

    rm -f signkey.ctx
    rm -f child.*
    shut_down
}
trap cleanup EXIT

start_up

test_createmldsa(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear

	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -u child.pub -r child.priv -R

	tpm2 load -C signkey.ctx -u child.pub -r child.priv -c child.ctx -R

}

test_createmlkem(){
	alg="$1"
	alg2="$2"
	tpm2 clear

	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt' -u child.pub -r child.priv -R

	tpm2 load -C signkey.ctx -u child.pub -r child.priv -c child.ctx -R

}

test_createmldsa mldsa44 sha256
test_createmldsa mldsa65 sha256
test_createmldsa mldsa44 sha512
test_createmldsa mldsa65 sha512

test_createmlkem mlkem512 sha256
test_createmlkem mlkem768 sha256
test_createmlkem mlkem1024 sha256
test_createmlkem mlkem512 sha512
test_createmlkem mlkem768 sha512
test_createmlkem mlkem1024 sha512

exit 0
