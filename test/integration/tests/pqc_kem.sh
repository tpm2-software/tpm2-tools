# SPDX-License-Identifier: BSD-3-Clause
#!/usr/bin/env bash 

source helpers.sh

cleanup() {

    rm -f key_*.ctx
    rm -f ct_*.bin ss_enc_*.bin ss_dec_*.bin
    shut_down
}
trap cleanup EXIT

start_up

test_mlkem(){
	tpm2_flushcontext -l
	tpm2_clear
	alg="$1"
	alg2="$2"
	
	ctx="key_${alg}.ctx"
	ct="ct_${alg}.bin"
	ss_enc="ss_enc_${alg}.bin"
	ss_dec="ss_dec${alg}.bin"

	#Create mlkem key
	tpm2 createprimary -C o -G "$alg" -g "$alg2" -c "$ctx" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt'

	#Test TPM2_Encapsulate 
	tpm2_encapsulate -c "$ctx" -t "$ct" -s "$ss_enc"
	test -s "$ct"
	test -s "$ss_enc"

	# Test TPM2_Decapsulate
	tpm2_decapsulate -c "$ctx" --ciphertext="$ct" --shared-secret="$ss_dec"
	test -s "$ss_dec"

	cmp "$ss_enc" "$ss_dec"
	

	
}

test_loadexternal_mlkem(){
	
	alg="$1"
	alg2="$2"
	
	ctx="key_${alg}.ctx"
	ct="ct_${alg}.bin"
	ss_enc="ss_enc_${alg}.bin"
	ss_dec="ss_dec${alg}.bin"
	
	tpm2 clear
	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -a 'sensitivedataorigin|userwithauth|decrypt' -u child.pub -r child.priv 
	tpm2 flushcontext -t
	tpm2 load -C signkey.ctx -u child.pub -r child.priv -c child.ctx
	tpm2 flushcontext -t
	tpm2 readpublic -c child.ctx -o mlkem.pub
	tpm2 flushcontext -t
	tpm2 loadexternal -C o -u mlkem.pub -c mlkem.ctx -n mlkem.name
	
	#Test TPM2_Encapsulate 
	tpm2_encapsulate -c mlkem.ctx -t "$ct" -s "$ss_enc"
	test -s "$ct"
	test -s "$ss_enc"

	# Test TPM2_Decapsulate
	tpm2_decapsulate -c child.ctx --ciphertext="$ct" --shared-secret="$ss_dec"
	test -s "$ss_dec"

	cmp "$ss_enc" "$ss_dec"

	
	tpm2 clear
	tpm2 flushcontext -t
	tpm2 flushcontext -l
	
}

test_mlkem mlkem512 sha256
test_mlkem mlkem768 sha256
test_mlkem mlkem1024 sha256
test_mlkem mlkem512 sha512
test_mlkem mlkem768 sha512
test_mlkem mlkem1024 sha512

test_loadexternal_mlkem mlkem512 sha256
test_loadexternal_mlkem mlkem768 sha256
test_loadexternal_mlkem mlkem1024 sha256
test_loadexternal_mlkem mlkem512 sha512
test_loadexternal_mlkem mlkem768 sha512
test_loadexternal_mlkem mlkem1024 sha512

exit 0
