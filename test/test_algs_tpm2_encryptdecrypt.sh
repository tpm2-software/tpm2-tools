#!/bin/sh

##before this script, you should make sure all kinds of context already loaded 

context_p=
halg=

ctx_count=`ls |grep -c context_load`
if [ $ctx_count -le 1 ];then
	echo "we should execute test_algs.sh first!"
	wait 5
    ./test_algs.sh
fi

rm test_algs_encryptdecrypt_*.log

#for  halg_p in 0x0004 0x000B 0x000C 0x000D 0x0012  
for  context_p in `ls context_load*`   
  do
	
	./tpm2_encryptdecrypt -c  $context_p  -D NO -I secret.data -o endecrypt_"$context_p".f


	 if [ $? != 0 ];then
	 echo "encryptdecrypt  for  endecrypt_"$context_p".f fail, pelase check the environment or parameters!"
	 echo "encryptdecrypt  for  endecrypt_"$context_p".f fail" >>test_encryptdecrypt_error.log
	else
	 echo "encryptdecrypt  for  endecrypt_"$context_p".f pass" >>test_encryptdecrypt_pass.log
   ./tpm2_encryptdecrypt -c  $context_p  -D YES -I  endecrypt_"$context_p".f -o decrypt_"$context_p".f
	
	  if [ $? != 0 ];then
	  echo "encryptdecrypt  for  decrypt_"$context_p".f fail, pelase check the environment or parameters!"
	  echo "encryptdecrypt  for  decrypt_"$context_p".f fail" >>test_encryptdecrypt_error.log
	 else
	  echo "encryptdecrypt  for  decrypt_"$context_p".f pass" >>test_encryptdecrypt_pass.log
	 fi
	fi

 done
