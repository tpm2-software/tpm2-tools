#!/bin/bash
handle_ek=0x8101000b
handle_ak=0x8101000c
ek_alg=0x001
ak_alg=0x0001
digestAlg=0x000B 
signAlg=0x0014
output_ek_pub=ek_pub.out
output_ak_pub=ak_pub.out
output_ak_pub_name=ak_name_pub.out

rm $output_ek_pub $output_ak_pub $output_ak_pub_name -rf 

 tpm2_getpubek  -H $handle_ek -g $ek_alg -f $output_ek_pub 
if [ $? != 0 ] || [ ! -e $output_ek_pub ];then
echo "getpubek fail, pelase check the environment or parameters!"
exit 1
fi

tpm2_getpubak  -E $handle_ek  -k $handle_ak -g $ak_alg -D $digestAlg -s $signAlg -f $output_ak_pub  -n $output_ak_pub_name 

if [ $? != 0 ] || [ ! -e $output_ak_pub ];then
echo "getpubak fail, pelase check the environment or parameters!"
exit 1
fi
 
echo "getpubak successfully!"


