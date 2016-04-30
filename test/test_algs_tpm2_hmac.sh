#!/bin/sh
context_p=
halg=
ctx_count=

ctx_count=`ls |grep -c context_load`
if [ $ctx_count -le 1 ];then
	echo "we should execute test_algs.sh first!"
	wait 5
    ./test_algs.sh
fi
rm -f test_hmac_*.log

#for  halg_p in 0x0004 0x000B 0x000C 0x000D 0x0012  
for  context_p in `ls context_load*`   
  do
   for halg in 0x0004 0x000B 0x000C
     do
	
##  echo "halg_p: "$halg_p" kalg_p: "$kalg_p"" >>test.log 
 tpm2_hmac  -c $context_p  -g $halg -I secret.data -o hmac_out_"$context_p"_"$halg_h"
	if [ $? != 0 ];then
	echo "hmac for hmac_out_"$context_p"_"$halg" fail, pelase check the environment or parameters!"
	echo "hmac for hmac_out_"$context_p"_"$halg" fail" >>test_hmac_error.log
	else
	echo "hmac for hmac_out_"$context_p"_"$halg" pass" >>test_hmac_pass.log
   fi

 done
done
