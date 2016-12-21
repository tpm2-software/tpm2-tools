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
#!/bin/sh
new_path=`dirname $0`
PATH="$PATH":"$new_path"

ekHandle=0x81010007 
akHandle=0x81010008 
 

fail()
{
	    echo "$1 test fail, please check the environment or parameters!"
 exit 1
}
Pass()
{
	    echo ""$1" pass" >>test_getpubak_pass.log
}


rm *.out

tpm2_takeownership -c

  if [ $? != 0 ];then
	fail takeownership 
  fi

test_tpm2_nv.sh

tpm2_getpubek  -H $ekHandle  -g 0x01 -f ek.pub1.out 

  if [ $? != 0 ];then
	fail getpubek 
  fi


tpm2_getpubak  -E $ekHandle -k $akHandle -f ak.pub1.out -n ak.name_1.out |tee output_ak
  if [ $? != 0 ] || [ ! -e ak.name_1.out ];then
	fail getpubak 
  fi
 
  grep  -A 3 "Name of loaded key:" output_ak|tr "\n" " " >grep.txt
  Loadkeyname=`sed -e 's/ //g'  grep.txt | awk  -F':' '{print $2}'`

echo 123456 | xxd -r -ps > secret.data
tpm2_makecredential -e ek.pub1.out  -s secret.data  -n $Loadkeyname -o makecredential.out

  if [ $? != 0 ];then
	fail makecredential
  fi

 
tpm2_activatecredential  -H $akHandle -k $ekHandle -f makecredential.out  -o act_credential.out 
  if [ $? != 0 ];then
	fail activatecredential
  fi

tpm2_akparse -f ak.pub1.out  -k akparse.out

  if [ $? != 0 ];then
	fail akparse 
  fi

##### getrandom & hash  
tpm2_getrandom -s 20 -o random.out
  if [ $? != 0 ];then
	fail getrandom 
  fi

tpm2_hash -H n -g 0x004 -I random.out -o hash.out -t hash_tk.out
  if [ $? != 0 ];then
	fail hash
  fi


############context ##############
###unseal
tpm2_createprimary -A p -g 0x0004 -G 0x001 -C context.p1.out
  if [ $? != 0 ];then
	fail createprimary
  fi

tpm2_create -c context.p1.out -g 0x000B -G 0x0008 -o opu1.out -O opr1.out -I secret.data 
  if [ $? != 0 ];then
	fail create
  fi
tpm2_load -c context.p1.out  -u opu1.out -r opr1.out -n name.load.1.out -C context_load_out1.out
  if [ $? != 0 ];then
	fail load
  fi
tpm2_unseal -c context_load_out1.out -o usl.data.out
  if [ $? != 0 ];then
	fail unseal
  fi

  #####quote
tpm2_createprimary -A p -g 0x000B -G 0x001 -C context.p2.out
  if [ $? != 0 ];then
	fail createprimary 
  fi
tpm2_create -c context.p2.out -g 0x000B -G 0x0008 -o opu2.out -O opr2.out 
  if [ $? != 0 ];then
	fail create 
  fi
tpm2_load -c context.p2.out  -u opu2.out -r opr2.out -n name.load_2.out -C context_load_out2.out
  if [ $? != 0 ];then
	fail load
  fi
tpm2_quote -c context_load_out2.out -g 0x4 -l 16,17,18 -o quote_outFile.out
  if [ $? != 0 ];then
	fail quote
  fi

######Hmac
tpm2_createprimary -A e -g 0x000B -G 0x0001 -C context.p3.out
  if [ $? != 0 ];then
	fail createprimary 
  fi
tpm2_create  -c  context.p3.out -g 0x000B -G 0x0008  -o opu3.out -O opr3.out
  if [ $? != 0 ];then
	fail create 
  fi
tpm2_load -c context.p3.out  -u opu3.out -r opr3.out -n name.load.3.out -C context_load_out3.out
  if [ $? != 0 ];then
	fail load 
  fi
tpm2_hmac  -c context_load_out3.out  -g 0x00B -I secret.data -o hmac.out
  if [ $? != 0 ];then
	fail hmac 
  fi

######readpublic
tpm2_createprimary -A e -g 0x000B -G 0x0001 -C context.p4.out
  if [ $? != 0 ];then
	fail createprimary 
  fi
tpm2_create  -c  context.p4.out -g 0x000B -G 0x0008  -o opu4.out -O opr4.out
  if [ $? != 0 ];then
	fail create 
  fi
tpm2_load -c context.p4.out  -u opu4.out -r opr4.out -n name.load.4.out -C context_load_out4.out
  if [ $? != 0 ];then
	fail load 
  fi
tpm2_readpublic -c context_load_out4.out -o rd-opu.out
  if [ $? != 0 ];then
	fail readpublic 
  fi

######evictcontrol
tpm2_createprimary -A e -g 0x000B -G 0x0001 -C context.p5.out
  if [ $? != 0 ];then
	fail createprimary 
  fi
tpm2_create -g 0x000B -G 0x0008 -o opu5.out -O opr5.out -c context.p5.out
  if [ $? != 0 ];then
	fail create 
  fi
tpm2_load -c context.p5.out  -u opu5.out -r opr5.out -n name.load5.out -C context_load_out5.out
  if [ $? != 0 ];then
	fail load 
  fi
tpm2_evictcontrol -A o -c context_load_out5.out  -S 0x81010003
  if [ $? != 0 ];then
	fail evictontronl
  else 
tpm2_evictcontrol -A o -H 0x81010003  -S 0x81010003
    if [ $? != 0 ];then
	 fail evictcontrol_release_Handle 
    fi
  fi

#####rsaencrypt & rsadecrypt
tpm2_createprimary -A e -g 0x000B -G 0x0001 -C context.p6.out
  if [ $? != 0 ];then
	fail createprimary 
  fi
tpm2_create  -g 0x000B -G 0x0001 -o opu6.out -O opr6.out -c context.p6.out
  if [ $? != 0 ];then
	fail create 
  fi
tpm2_loadexternal  -H n -u opu6.out -C context_loadexternal_out6.out
  if [ $? != 0 ];then
	fail loadexternal 
  fi
tpm2_rsaencrypt -c context_loadexternal_out6.out -I secret.data -o rsa_en.out
  if [ $? != 0 ];then
	fail rsa_encrypt 
  fi
tpm2_load -c context.p6.out  -u opu6.out -r opr6.out -n name.load6.out -C context_load_out6.out
  if [ $? != 0 ];then
	fail load 
  fi
tpm2_rsadecrypt -c context_load_out6.out  -I rsa_en.out -o rsa_de.out
  if [ $? != 0 ];then
	fail rsa_decrypt 
  fi

#####sign
tpm2_createprimary -A e -g 0x000B -G 0x0001 -C context.p7.out
  if [ $? != 0 ];then
	fail createprimary 
  fi
  
tpm2_create -g 0x000B -G 0x0008 -o opu7.out -O opr7.out -c context.p7.out
  if [ $? != 0 ];then
	fail create 
  fi
tpm2_load -c context.p7.out  -u opu7.out -r opr7.out -n name.load7.out -C context_load_out7.out
  if [ $? != 0 ];then
	fail load 
  fi
tpm2_sign -c context_load_out7.out -g 0x00B -m secret.data -s sign.f.out
  if [ $? != 0 ];then
	fail sign 
  fi

tpm2_verifysignature -c context_load_out7.out  -g 0x000B -m secret.data  -s sign.f.out -t tickt_verify_sign.out 
  if [ $? != 0 ];then
	fail verifysignature
  fi

######encryptdecrypt
tpm2_createprimary -A e -g 0x000B -G 0x0001 -C context.p8.out
  if [ $? != 0 ];then
	fail createprimary 
  fi
tpm2_create  -g 0x000B -G 0x0025 -o opu8.out -O opr8.out -c context.p8.out
  if [ $? != 0 ];then
	fail create 
  fi
tpm2_load -c context.p8.out  -u opu8.out -r opr8.out -n name.load8.out -C context_load_out8.out
  if [ $? != 0 ];then
	fail load 
  fi
tpm2_encryptdecrypt -c context_load_out8.out -D NO -I secret.data -o endecrypt.out
  if [ $? != 0 ];then
	fail encrypt 
  fi
tpm2_encryptdecrypt -c context_load_out8.out -D YES -I endecrypt.out -o endecrypt_de.out
  if [ $? != 0 ];then
	fail decrypt
  fi

######certify
tpm2_createprimary -A e -g 0x000B -G 0x0001 -C context.p9.out
  if [ $? != 0 ];then
	fail createprimary 
  fi
tpm2_create -g 0x000B -G 0x0001 -o opu9.out -O opr9.out -c context.p9.out 
  if [ $? != 0 ];then
	fail create 
  fi
tpm2_load -c context.p9.out  -u opu9.out -r opr9.out -n name.load9.out -C context_load_out9.out -d 3
  if [ $? != 0 ];then
	fail load 
  fi
tpm2_certify -C context.p9.out -c context_load_out9.out -g 0x000B -a attest.out -s certify_signature.out
  if [ $? != 0 ];then
	fail certify 
  fi

tpm2_listpcrs 
  if [ $? != 0 ];then
	fail listpcrs
  fi
