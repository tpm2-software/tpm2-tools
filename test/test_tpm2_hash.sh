#!/bin/sh

#this script is for hash case testing 
halg=0x000B
Hierarchy=e

rm -f  hash_out_"$Hierarchy"_"$halg" hash_tk_"$Hierarchy"_"$halg" 

if [ ! -f hash.in ];then
echo "T0naX0u123abc" >hash.in
fi

	
tpm2_hash -H $Hierarchy -g $halg -I hash.in -o hash_out_"$Hierarchy"_"$halg" -t hash_tk_"$Hierarchy"_"$halg"
if [ $? != 0 ];then
	    echo "hash forHierarchy:"$Hierarchy"halg:"$halg" fail, pelase check the environment or parameters!"
		exit 1
else
	    echo "hash for Hierarchy:"$Hierarchy"halg:"$halg" succed"
fi
	



