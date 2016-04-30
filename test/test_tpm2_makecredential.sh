#!/bin/bash
handle_ek=0x81010007
handle_ak=0x81010008
ek_alg=0x001
ak_alg=0x0001
digestAlg=0x000B 
signAlg=0x0014

file_input_data=secret.data
output_ek_pub=ek_pub.out
output_ak_pub=ak_pub.out
output_ak_pub_name=ak_name_pub.out
output_mkcredential=mkcredential.out

rm $output_ek_pub $output_ak_pub $output_ak_pub_name $output_mkcredential -rf 

if [ ! -e "$file_input_data" ]   
  then    
  echo "12345678" > $file_input_data
fi 

tpm2_getpubek  -H $handle_ek -g $ek_alg -f $output_ek_pub 
if [ $? != 0 ] || [ ! -e $output_ek_pub ];then
	echo "getpubek fail, pelase check the environment or parameters!"
	exit 1
fi

tpm2_getpubak  -E $handle_ek  -k $handle_ak -g $ak_alg -D $digestAlg -s $signAlg -f $output_ak_pub  -n $output_ak_pub_name |tee output_ak 

if [ $? != 0 ] || [ ! -e output_ak ];then
	echo "getpubak fail, pelase check the environment or parameters!"
	exit 1
fi
grep  -A 3 "Name of loaded key:" output_ak|tr "\n" " " >grep.txt
Loadkeyname=`sed -e 's/ //g'  grep.txt | awk  -F':' '{print $2}'`

tpm2_makecredential -e $output_ek_pub  -s $file_input_data  -n $Loadkeyname -o $output_mkcredential

if [ $? != 0 ];then
	echo "makecredential fail, pelase check the environment or parameters!"
	exit 1
fi

echo "makecredential successfully!"


