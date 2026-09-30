# SPDX-License-Identifier: BSD-3-Clause
#!/usr/bin/env bash 

source helpers.sh

cleanup() {

    rm -f *.ctx
    rm -f obj.* mldsa.* mlkem.* signer.*
    rm -f *.out
    rm -f attestat.ion
    rm -f sig.nature
    rm -f creation.hash
    shut_down
}
trap cleanup EXIT

start_up

test_certify_mldsa_mlkem(){
	alg_mldsa="$1"
	alg_mlkem="$2"
	alg="$3"
		
	tpm2 clear
	tpm2 createprimary -C o -G rsa -g "$3" -c primary.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C primary.ctx -g "$3" -G "$2" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt' -u mlkem.pub -r mlkem.priv -R

	tpm2 load -C primary.ctx -u mlkem.pub -r mlkem.priv -c mlkem.ctx -R
	tpm2 create -C primary.ctx -g "$3" -G "$1" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -u mldsa.pub -r mldsa.priv --creation-data obj.creation.data --creation-hash obj.creation.hash --creation-ticket obj.creation.ticket -R

	tpm2 load -C primary.ctx -u mldsa.pub -r mldsa.priv -c mldsa.ctx -R

	tpm2 certify -c mlkem.ctx -C mldsa.ctx -g "$3" -o attest.out -s sig.out --scheme=mldsa

}

test_certifycreation(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear

	tpm2 createprimary -C o -G rsa -g "$2" -c primary.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C primary.ctx -g "$2" -G rsa -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt' -u obj.pub -r obj.priv --creation-data obj.creation.data --creation-hash obj.creation.hash --creation-ticket obj.creation.ticket -R

	tpm2 load -C primary.ctx -u obj.pub -r obj.priv -c obj.ctx -R
	tpm2 create -C primary.ctx -g "$2" -G "$1" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -u mldsa.pub -r mldsa.priv -R

	tpm2 load -C primary.ctx -u mldsa.pub -r mldsa.priv -c mldsa.ctx -R

	tpm2 certifycreation -c obj.ctx -C mldsa.ctx -d obj.creation.hash -t obj.creation.ticket -g "$2" -o sig.nature --scheme=mldsa --attestation=attestat.ion

}

test_certify_mldsa_mlkem mldsa44 mlkem512 sha256
test_certify_mldsa_mlkem mldsa44 mlkem768 sha256
test_certify_mldsa_mlkem mldsa44 mlkem1024 sha256
test_certify_mldsa_mlkem mldsa44 mlkem512 sha512
test_certify_mldsa_mlkem mldsa44 mlkem768 sha512
test_certify_mldsa_mlkem mldsa44 mlkem1024 sha512

test_certify_mldsa_mlkem mldsa65 mlkem512 sha256
test_certify_mldsa_mlkem mldsa65 mlkem768 sha256
test_certify_mldsa_mlkem mldsa65 mlkem1024 sha256
test_certify_mldsa_mlkem mldsa65 mlkem512 sha512
test_certify_mldsa_mlkem mldsa65 mlkem768 sha512
test_certify_mldsa_mlkem mldsa65 mlkem1024 sha512

test_certifycreation mldsa44 sha256
test_certifycreation mldsa65 sha256
test_certifycreation mldsa44 sha512
test_certifycreation mldsa65 sha512

exit 0
