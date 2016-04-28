#!/bin/sh

#this script is for hash case testing 
halg=
Hierarchy=

rm test_hash.log

if [ ! -f hash.in ];then
echo "T0naX0u123abc" >hash.in
fi

for Hierarchy in e o p n  
do
	for halg in 0x0004 0x000B 0x000C 0x000D 0x0012
	do
	
	tpm2_hash -H $Hierarchy -g $halg -I hash.in -o hash_out_"$Hierarchy"_"$halg" -t hash_tk_"$Hierarchy"_"$halg"
	if [ $? != 0 ];then
	    echo "hash for hash_out_"$Hierarchy"_"$halg" fail, pelase check the environment or parameters!"
	 else
	    echo "hash for hash_out_"$Hierarchy"_"$halg" pass" >>test_hash_pass.log
	fi
	
	 done
done



