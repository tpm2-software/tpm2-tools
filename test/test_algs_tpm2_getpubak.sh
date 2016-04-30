#!/bin/bash
handle_ek=0x81010005
##ek_e=1
ek_alg=0x0001

handle_ak=0x81010006
ak_alg=
digestAlg= 
signAlg=

fail()
{
	echo "$1 test fail, pelase check the environment or parameters!"
	echo ""$1" fail" >>test_getpubak_error.log
}	

Pass()
{
	echo ""$1" pass" >>test_getpubak_pass.log
}


rm test_getpub*.log
rm ak.pub*

tpm2_getpubek  -H "$handle_ek" -g $ek_alg -f ek.pub_"$ek_alg" 
if [ $? != 0 ];then
    fail getpubek
	exit 1
fi
##   ./tpm2_getpubak  -e "$handle_ek" -k $handle_ak  -g $ak_alg -D $digestAlg -s $signAlg -f ak.pub_"$kalg_p"_"$halg"_"$digestAlg"_"$signAlg" -n ak.name_"$kalg_p"_"$halg"_"$digestAlg"_"$signAlg"

for  ak_alg in 0x0001 0x0008 0x0023  
 do
   for  digestAlg in 0x0004 0x000B 0x000C 0x000D 0x0012
   do 
    for  signAlg in 0x0005 0x0014 0x0016 0x0018 0x001A 0x001B 0x001C
    do

   ./tpm2_getpubak  -E "$handle_ek" -k $handle_ak  -g $ak_alg -D $digestAlg -s $signAlg -f ak.pub_"$ak_alg"_"$digestAlg"_"$signAlg" -n ak.name_"$ak_alg"_"$digestAlg"_"$signAlg"
  if [ $? != 0 ];then
    fail "Ak_alg_"$ak_alg"_"$digestAlg"_"$signAlg""
  else
    Pass "Ak_alg_"$ak_alg"_"$digestAlg"_"$signAlg""
  fi
  handle_ak=$(($handle_ak+0x1))
  val=`echo 'obase=16; '$handle_ak''|bc`
  handle_ak=0x"$val"
  done
 done
done

