#!/bin/sh
context_p=

halg_p=
kalg_p=

halg_c=
kalg_c=

rm *.log  context*  op* name.load*


for  halg_p in 0x0004 0x000B 0x000C 0x000D 0x0012  
   do
    for kalg_p in 0x0001 0x0008 0x0023 0x0025
      do
 
     tpm2_createprimary -A p -g $halg_p  -G $kalg_p -C context.p_"$halg_p"_"$kalg_p"
     if [ $? != 0 ];then
     echo "createprimary for context.p_"$halg_p"_"$kalg_p" fail, pelase check the environment or      parameters!"
     continue 
	 fi
 
 ############create & load key context############ 
 for  halg_c in 0x0004 0x000B 0x000C 0x000D 0x0012
 do
	for kalg_c in 0x0001 0x0008 0x0023 0x0025
	 do
     tpm2_create  -g $halg_c  -G $kalg_c -o opu_"$halg_p""$kalg_p"_"$halg_c""$kalg_c" -O opr_"$halg_p""$kalg_p"_"$halg_c""$kalg_c"  -I secret.data  -c context.p_"$halg_p"_"$kalg_p"
    
		if [ $? != 0 ];then
		echo "create used context.p_"$halg_p"_"$kalg_p" with algs:"$halg_c""$kalg_c" fail, pelase check the environment or parameters!" 
		echo "create used context.p_"$halg_p"_"$kalg_p" with algs:"$halg_c""$kalg_c" fail" >>create_error.log 

	else

		 tpm2_load -c context.p_"$halg_p"_"$kalg_p"  -u opu_"$halg_p""$kalg_p"_"$halg_c""$kalg_c"  -r opr_"$halg_p""$kalg_p"_"$halg_c""$kalg_c"  -n name.load_"$halg_p""$kalg_p"_"$halg_c""$kalg_c" -C context_load_"$halg_p""$kalg_p"_"$halg_c""$kalg_c"
		if [ $? != 0 ];then
		echo "load for context.p_"$halg_p"_"$kalg_p"  fail, pelase check the environment or      parameters!"
		echo "load context.p_"$halg_p"_"$kalg_p" for create  context_load_"$halg_p""$kalg_p"_"$halg_c""$kalg_c" fail" >>load_error.log
		fi
	
     fi
	 done
	done

 done
done

#ctx_count=`ls |grep -c context_load`
#if [ $ctx_count -le 1 ];then
#	echo "we should execute test_algs.sh first!"
#	wait 5
#    ./test_algs.sh
#fi

rm test_unseal_*.log  usl_* 

for  context_p in `ls context_load*`   
do
  
  tpm2_unseal -c $context_p -o usl_"$context_p".out
  if [ $? != 0 ];then
      echo "unseal fail, pelase check the environment or parameters!"
      echo "unseal for_"$context_p" fail" >>test_unseal_error.log
   else
      echo "unseal for_"$context_p" pass" >>test_unseal_pass.log
  fi

done
