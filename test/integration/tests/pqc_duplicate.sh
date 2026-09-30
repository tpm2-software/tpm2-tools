# SPDX-License-Identifier: BSD-3-Clause
#!/usr/bin/env bash 

source helpers.sh

cleanup() {

    rm -f *.ctx
    rm -f new_parent.*
    rm -f *.dat key.* dup.* duplicate.priv
    shut_down
}
trap cleanup EXIT

start_up

test_duplicate_mlkem(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear
	
	#TPM createprimary
	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx 
	
	#TPM create
	tpm2 create -C signkey.ctx -g "$2" -G rsa -a 'restricted|sensitivedataorigin|userwithauth|decrypt' -u new_parent.pub -r new_parent.priv -R
	
	#TPM load
	tpm2 load -C signkey.ctx -u new_parent.pub -r new_parent.priv -c new_parent.ctx -R
	
	#startauthsession
	tpm2 startauthsession -S session.dat
	
	#policycommand
	tpm2 policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
	tpm2 flushcontext session.dat
	
	#TPM create mlkem
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -p foo -r key.prv -u key.pub -L dpolicy.dat -a 'sensitivedataorigin|userwithauth|decrypt' -R
	
	#TPM load
	tpm2 load -C signkey.ctx -r key.prv -u key.pub -c key.ctx -R
	#TPM readpublic
	tpm2 readpublic -c key.ctx -o dup.pub
	#TPM startauthsession
	tpm2 startauthsession --policy-session -S session.dat
	tpm2 policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
	#TPM duplicate
	tpm2 flushcontext -t
	tpm2 duplicate -C new_parent.ctx -c key.ctx -G null -r duplicate.priv -s seed.dat -p "session:session.dat"

	#TPM import
	tpm2 import -C new_parent.ctx -u dup.pub -i duplicate.priv -r dup.prv -s seed.dat -L dpolicy.dat

}

test_duplicate_mldsa(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear
	#TPM createprimary
	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx 
	#TPM create
	tpm2 create -C signkey.ctx -g "$2" -G rsa -a 'restricted|sensitivedataorigin|userwithauth|decrypt' -u new_parent.pub -r new_parent.priv -R
	#TPM load
	tpm2 load -C signkey.ctx -u new_parent.pub -r new_parent.priv -c new_parent.ctx -R
	#startauthsession
	tpm2 startauthsession -S session.dat
	#policycommand
	tpm2 policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
	tpm2 flushcontext session.dat
	#TPM create mldsa
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -p foo -r key.prv -u key.pub -L dpolicy.dat -a 'sensitivedataorigin|userwithauth|sign' -R
	#TPM load
	tpm2 load -C signkey.ctx -r key.prv -u key.pub -c key.ctx -R
	#TPM readpublic
	tpm2 readpublic -c key.ctx -o dup.pub
	#TPM startauthsession
	tpm2 startauthsession --policy-session -S session.dat
	tpm2 policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
	#TPM duplicate
	tpm2 flushcontext -t
	tpm2 duplicate -C new_parent.ctx -c key.ctx -G null -r duplicate.priv -s seed.dat -p "session:session.dat"
	#TPM import
	tpm2 import -C new_parent.ctx -u dup.pub -i duplicate.priv -r dup.prv -s seed.dat -L dpolicy.dat
}
test_duplicate_mlkem mlkem512 sha256
test_duplicate_mlkem mlkem768 sha256
test_duplicate_mlkem mlkem1024 sha256

test_duplicate_mldsa mldsa44 sha256
test_duplicate_mldsa mldsa65 sha256

exit 0
