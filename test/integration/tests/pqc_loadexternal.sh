# SPDX-License-Identifier: BSD-3-Clause
#!/usr/bin/env bash 

source helpers.sh

cleanup() {

    rm -f *.ctx
    rm -f child.*
    rm -f mldsa.* mlkem.*
    shut_down
}
trap cleanup EXIT

start_up

test_loadexternal_mldsa(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear
	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -a 'sensitivedataorigin|userwithauth|sign' -u child.pub -r child.priv -p foo -R
	tpm2 load -C signkey.ctx -u child.pub -r child.priv -c child.ctx -R

	tpm2 readpublic -c child.ctx -o mldsa.pub

	tpm2 loadexternal -C o -u mldsa.pub -c mldsa.ctx -n mldsa.name -R
	
}

test_loadexternal_mlkem(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear
	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -a 'sensitivedataorigin|userwithauth|decrypt' -u child.pub -r child.priv -p foo -R

	tpm2 load -C signkey.ctx -u child.pub -r child.priv -c child.ctx -R

	tpm2 readpublic -c child.ctx -o mlkem.pub

	tpm2 loadexternal -C o -u mlkem.pub -c mlkem.ctx -n mlkem.name -R
	
}
test_loadexternal_mldsa mldsa44 sha256
test_loadexternal_mldsa mldsa65 sha256
test_loadexternal_mldsa mldsa44 sha512
test_loadexternal_mldsa mldsa65 sha512

test_loadexternal_mlkem mlkem512 sha256
test_loadexternal_mlkem mlkem768 sha256
test_loadexternal_mlkem mlkem1024 sha256
test_loadexternal_mlkem mlkem512 sha512
test_loadexternal_mlkem mlkem768 sha512
test_loadexternal_mlkem mlkem1024 sha512

exit 0
