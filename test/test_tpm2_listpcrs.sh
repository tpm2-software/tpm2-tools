#!/bin/bash


tpm2_listpcrs 

if [ $? != 0 ];then 
 echo "listpcrs  fail!"
 exit 1
else
 echo "listpcrs  OK!"
fi
