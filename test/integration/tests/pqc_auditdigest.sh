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

test_getcommandauditdigest(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear
	tpm2 flushcontext -t
	tpm2 flushcontext -l
	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -u child.pub -r child.priv
	tpm2 flushcontext -t
	tpm2 load -C signkey.ctx -u child.pub -r child.priv -c child.ctx
	tpm2 setcommandauditstatus -C p -g "$2" TPM2_CC_GetRandom
	tpm2 getrandom --hex 10
	tpm2 getcommandauditdigest -c child.ctx -m audit.attes --scheme=mldsa -s signature.out
	tpm2 clear
	tpm2 flushcontext -t
	tpm2 flushcontext -l
}

test_getsessionauditdigest(){
	alg="$1"
	alg2="$2"
	
	tpm2 clear
	tpm2 flushcontext -t
	tpm2 flushcontext -l
	tpm2 createprimary -C o -G rsa -g "$2" -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt'
	tpm2 create -C signkey.ctx -g "$2" -G "$1" -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -u child.pub -r child.priv
	tpm2 flushcontext -t
	tpm2 load -C signkey.ctx -u child.pub -r child.priv -c child.ctx
	tpm2 startauthsession -S mysession.ctx --audit-session
	tpm2 getrandom --hex 10 -S mysession.ctx
	tpm2 getsessionauditdigest -c child.ctx --scheme=mldsa -S mysession.ctx -m session_audit.attest -s session_audit.sig 
	tpm2 clear
	tpm2 flushcontext -t
	tpm2 flushcontext -l
}
test_getcommandauditdigest mldsa44 sha256
test_getcommandauditdigest mldsa65 sha256
test_getcommandauditdigest mldsa44 sha512
test_getcommandauditdigest mldsa65 sha512 

test_getsessionauditdigest mldsa44 sha256
test_getsessionauditdigest mldsa65 sha256
test_getsessionauditdigest mldsa44 sha512
test_getsessionauditdigest mldsa65 sha512 

exit 0
