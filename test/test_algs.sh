###this script use for test the implementation of all algorithms involved createprimary &create/load 

#!/bin/sh
halg_p=
kalg_p=

halg_c=
kalg_c=

rm *.log  context*  op* name.load*

for  halg_p in 0x0004 0x000B 0x000C 0x000D 0x0012  
# for  halg_p in 0x0004 0x000B 0x000C
   do
    for kalg_p in 0x0001 0x0008 0x0023 0x0025
      do
 
     tpm2_createprimary -A e -g $halg_p  -G $kalg_p -C context.p_"$halg_p"_"$kalg_p"
     if [ $? != 0 ];then
     echo "createprimary for context.p_"$halg_p"_"$kalg_p" fail, pelase check the environment or      parameters!"
     fi
 
 ############create & load key context############ 
 for  halg_c in 0x0004 0x000B 0x000C 0x000D 0x0012
 do
	for kalg_c in 0x0001 0x0008 0x0023 0x0025
	 do
     tpm2_create  -g $halg_c  -G $kalg_c -o opu_"$halg_p""$kalg_p"_"$halg_c""$kalg_c" -O opr_"$halg_p""$kalg_p"_"$halg_c""$kalg_c"  -c context.p_"$halg_p"_"$kalg_p"
    
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
