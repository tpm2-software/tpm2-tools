#!/bin/bash
handle_ek=0x81010005
ek_alg=0x001
output_ek_pub=ek_pub.out

rm $output_ek_pub

 tpm2_getpubek  -H $handle_ek -g $ek_alg -f $output_ek_pub 
if [ $? != 0 ] || [ ! -e $output_ek_pub ];then
echo "getpubek fail, pelase check the environment or parameters!"
exit 1
fi

echo "getpubek successfully!"


