#!/bin/sh

size=32

rm -f  random.out

tpm2_getrandom -s 32  -o random.out 
if [ $? != 0 ];then
	    echo "getrandom test fail, pelase check the environment or parameters!"
		exit 1
else
	    echo "getrandom  succeed"
fi
	



