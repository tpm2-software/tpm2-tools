#!/bin/sh
#this script for tpm2_getrandom verification 

LOG_FILE=random_pass_count.log
 if [ -e "$LOG_FILE" ];then
  rm -f "$LOG_FILE"
 fi
i=

#for((i=1;i<=10;i++)); do
for i in `seq 100`; do
	tpm2_getrandom -s 32  -o random_"$i".out 
	 if  [ $? != 0 ];then
	  echo " create random_"$i".out fail, pelase check the environment or parameters!"
	  exit 2
	 else
	  echo  "create random_"$i".out Pass" >>$LOG_FILE
	 fi
done

for a in `seq 99` ;do
   b=$(($a+1)) 

	while [ $b -le 100 ]; do
	diff "random_"$a".out" "random_"$b".out" >/dev/null 
	 if [ $? -eq 0 ];then
	  echo "random test fial"
	  exit 1
	 fi
	b=$(($b+1))
	done

done 

echo  "random test Pass"
