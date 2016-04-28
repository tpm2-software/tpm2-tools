#!/bin/sh
#handle_e=0x81010003
handle_e=1
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

for  kalg_p in 0x0001 0x0008 0x0023 0x0025   
 do
	
  ./tpm2_getpubek  -H 0x8101000"$handle_e" -g $kalg_p -f ek.pub_"$kalg_p" 
  if [ $? != 0 ];then
    fail "$Kalg_p"
#	echo "getpubek  for ek.pub_"$kalg_p" fail, pelase check the environment or parameters!"
#	echo "getpubek  for ek.pub_"$kalg_p" fail" >>test_getpubek_error.log
	
  else
    Pass "Kalg_p"
#	echo "getpubek  for ek.pub_"$kalg_p" pass" >>test_getpubak_pass.log
    handle_k='expr $hanlde_p + 1'
    ./tpm2_getpubak  -e 0x8101000"$handle_e" -k 0x8101000"$handle_k"  -g $halg -D $digestAlg -s $signAlg -f ak.pub_"$kalg_p"_"$halg"_"$digestAlg"_"$signAlg" -n ak.name_"$kalg_p"_"$halg"_"$digestAlg"_"$signAlg"

  fi
	 handle_e='expr $hanlde_p + 2'
 done
