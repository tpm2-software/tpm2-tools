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


rm test_quote_*.log

for  context_p in `ls context_load*`   
  do
   for halg in 0x0004 0x000B 0x000C 0x000D 0x0012
     do
	
	tpm2_quote -c $context_p  -g $halg  -l 16,17,18 -o quote_out_"$context_p"_"$halg_h"_"$halg"
	if [ $? != 0 ];then
	echo "quote for quote_"$context_p"_"$halg"  fail, pelase check the environment or parameters!"
	echo " quote for quote_"$context_p"_"$halg" fail" >>test_quote_error.log
	else
	echo "quote for quote_"$context_p"_"$halg"  pass" >>test_quote_pass.log
   fi

 done
done
