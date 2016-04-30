#!/bin/bash
#handle_ek=0x81010003
ek_e=1
handle_k=
kalg_p=
halg=
digestAlg= 
signAlg=

fail()
{
	echo "getpubek  for ek.pub_"$1" fail, pelase check the environment or parameters!"
	echo "getpubek  for ek.pub_"$1" fail" >>test_getpubek_error.log
}	

Pass()
{
	echo "getpubek  for ek.pub_"$1" pass" >>test_getpubak_pass.log
}



rm test_getpub*.log
rm ek.pub*

for  kalg_p in 0x0001 0x0008 0x0023 0x0025   
 do
##echo $ek_e	
 tpm2_getpubek  -H 0x8101000"$ek_e" -g $kalg_p -f ek.pub_"$kalg_p" 
  if [ $? != 0 ];then
    fail "$kalg_p"
  else
    Pass "$kalg_p"
  fi
 ek_e=$(($ek_e+2))
 done
