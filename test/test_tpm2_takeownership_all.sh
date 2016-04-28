#!/bin/bash

ownerPasswd=abc123
endorsePasswd=abc123
lockPasswd=abc123
new_ownerPasswd=newpswd
new_endorsePasswd=newpswd
new_lockPasswd=newpswd


tpm2_takeownership -c 
 if [ $? != 0 ];then 
	echo "clean ownership Fail!"
	exit 1
 fi
 
 
tpm2_takeownership -o $ownerPasswd -e $endorsePasswd -l $lockPasswd
	if [ $? != 0 ];then
	 echo "take onwership Fail, check your envirnoment!"
	 exit 1
	fi



tpm2_takeownership -O $ownerPasswd -E $endorsePasswd -L $lockPasswd -o $new_ownerPasswd -e $new_endorsePasswd -l $new_lockPasswd
	if [ $? != 0 ];then
	 echo "re-take onwership Fail, check your envirnoment!"
	 exit 1
	fi 


