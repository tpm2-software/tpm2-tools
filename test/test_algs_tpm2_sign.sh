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

rm test_algs_sign_*.log sign_*

#for  halg_p in 0x0004 0x000B 0x000C 0x000D 0x0012  
for  context_p in `ls context_load*`   
  do
   for halg in 0x0004 0x000B 0x000C
     do
	
   tpm2_sign -c $context_p  -g $halg  -m secret.data -s sign_"$context_p"_"$halg_h"_"$halg"
	if [ $? != 0 ];then
	echo "sign for sign_"$context_p"_"$halg"  fail, pelase check the environment or parameters!"
	echo " sign for sign_"$context_p"_"$halg" fail" >>test_algs_sign_error.log
	else
	echo "sign for sign_"$context_p"_"$halg"  pass" >>test_algs_sign_pass.log
   fi

 done
done
