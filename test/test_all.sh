#;**********************************************************************;
#
# Copyright (c) 2016, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, 
# this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, 
# this list of conditions and the following disclaimer in the documentation 
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

####before this script, please make sure all test scripts copy here, TPM is initialized.

#!/bin/bash
new_path=`dirname $0`
PATH="$PATH":"$new_path"

rm test_all_pass.log test_all_fail.log

func()
{
$1
  if [ $? = 0 ];then
	clear
	echo -e "\033[32m $1 pass \033[0m"
	sleep 1 
	echo "$1 pass" >>test_all_pass.log
  else
	echo -e "\033[31m $1 Fail, press any key to continue.... \033[0m"
	echo "$1 fail" >>test_all_fail.log
	read
	fi
}
 
func  test_tpm2_takeownership_all.sh

func test_tpm2_nv.sh

func test_tpm2_listpcrs.sh

func test_tpm2_getrandom.sh

##func test_tpm2_createprimary_all.sh
##func test_tpm2_create_all.sh
func test_tpm2_load.sh
func test_tpm2_loadexternal.sh

func test_tpm2_evictcontrol.sh

func test_tpm2_hash.sh
func test_tpm2_hmac.sh

func test_tpm2_quote.sh
func test_tpm2_unseal.sh

func test_tpm2_akparse.sh
func test_tpm2_certify.sh

func test_tpm2_evictcontrol.sh
func test_tpm2_getpubek.sh
func test_tpm2_getpubak.sh

func test_tpm2_makecredential.sh
func test_tpm2_activecredential.sh
func test_tpm2_readpublic.sh
func test_tpm2_rsaencrypt.sh
func test_tpm2_rsadecrypt.sh

func test_tpm2_encryptdecrypt.sh
func test_tpm2_sign.sh
func test_tpm2_verifysignature.sh



