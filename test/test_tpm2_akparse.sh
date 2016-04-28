#!/bin/bash
 
new_path=`pwd`
PATH="$PATH":"$new_path"

file_input_data=ak_pub.out
output_akparse=akparse.out

rm $output_ekparse -rf 

if [ ! -e "$file_input_data" ]   
  then    
  test_tpm2_getpubak.sh
fi 

 tpm2_akparse -f $file_input_data  -k $output_akparse
if [ $? != 0 ];then
	echo "akparse fail, pelase check the environment or parameters!"
	exit 1
fi

echo "akparse successfully!"


