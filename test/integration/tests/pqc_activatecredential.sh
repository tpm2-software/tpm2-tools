# SPDX-License-Identifier: BSD-3-Clause
#!/usr/bin/env bash 

source helpers.sh

cleanup() {

    rm -f signkey.ctx
    rm -f child.*
    rm -f mlkem_act.name mlkem_protect.pub
    rm -f secret.bin recovered_secret.bin
    rm -f cred.out
    shut_down
}
trap cleanup EXIT

start_up

test_activatecredential(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear 
	
	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt' -u child.pub -r child.priv -R

	tpm2 load -C signkey.ctx -u child.pub -r child.priv -c child.ctx -R

	tpm2 readpublic -c child.ctx -n mlkem_act.name
	tpm2 readpublic -c signkey.ctx -o mlkem_protect.pub
	tpm2 flushcontext -t
	echo -n "helo world" > secret.bin
	tpm2 makecredential -u mlkem_protect.pub -n mlkem_act.name -s secret.bin -o cred.out

	tpm2 activatecredential -c child.ctx -C signkey.ctx -i cred.out -o recovered_secret.bin

}
test_activatecredential mlkem512 sha256
test_activatecredential mlkem768 sha256
test_activatecredential mlkem1024 sha256
test_activatecredential mlkem512 sha512
test_activatecredential mlkem768 sha512
test_activatecredential mlkem1024 sha512

exit 0
