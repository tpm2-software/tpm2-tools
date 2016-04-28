#!/bin/bash
 nv_test_index=0x1500018
 nv_auth_handle=0x40000001

tpm2_nvlist|grep -i $nv_test_index
if [ $? = 0 ];then
tpm2_nvrelease -x $nv_test_index -a $nv_auth_handle 
 if [ $? != 0 ];then 
	echo "please release the nv index $nv_test_index first!"
	exit 1
 fi
fi

tpm2_nvdefine -x $nv_test_index -a $nv_auth_handle -s 32 -t 0x2000A  
if [ $? != 0 ];then 
echo "nvdefine fail,Please check your environment!"
exit 1
fi


if [ ! -f nv.test_w ];then
echo "please123abc" >nv.test_w
fi

tpm2_nvwrite -x $nv_test_index -a $nv_auth_handle  -f nv.test_w 
if [ $? != 0 ];then 
echo "nvwrite fail!"
exit 1
fi

tpm2_nvread -x $nv_test_index -a $nv_auth_handle  -s 32 -o 0

if [ $? != 0 ];then 
echo "nvread fail!"
exit 1
fi

tpm2_nvlist|grep -i $nv_test_index
if [ $? != 0 ];then 
echo "nvlist  fail or double check the define index!"
exit 1
fi

tpm2_nvrelease -x $nv_test_index -a $nv_auth_handle  

if [ $? != 0 ];then 
 echo "nvrelease  fail or double check the define index!"
 exit 1
else
 echo "release the nv index OK!"
fi
