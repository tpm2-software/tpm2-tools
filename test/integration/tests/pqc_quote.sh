# SPDX-License-Identifier: BSD-3-Clause
#!/usr/bin/env bash 

source helpers.sh

cleanup() {

    rm -f *.ctx
    rm -f child.*
    shut_down
}
trap cleanup EXIT

start_up

test_quotemldsa(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear
	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -u child.pub -r child.priv -R
	tpm2 load -C signkey.ctx -u child.pub -r child.priv -c child.ctx -R
	tpm2 quote -c child.ctx -l 0x0004:16,17,18+0x000b:16,17,18 --scheme=mldsa
}

test_quotemldsa mldsa44 sha256
test_quotemldsa mldsa65 sha256
test_quotemldsa mldsa44 sha512
test_quotemldsa mldsa65 sha512 

exit 0
