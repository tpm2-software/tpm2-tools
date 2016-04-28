#!/bin/sh

Atype=
gAlg=
GAlg=

rm createprimary.error.log rf

for gAlg in 0x04 0x0B 0x0C 0x0D 0x12
    do 
        for GAlg in 0x01 0x08 0x23 0x25
            do 
                for Atype in o e p n 
                    do 
                    tpm2_createprimary -A $Atype -g $gAlg -G $GAlg -C ctx.cpri."$Atype".g"$gAlg".G"$GAlg"
                    if [ $? != 0 ];then 
                    echo "tpm2_createprimary error: Atype=$Atype gAlg=$gAlg GAlg=$GAlg"
                    echo "tpm2_createprimary error: Atype=$Atype gAlg=$gAlg GAlg=$GAlg" >> createprimary.error.log
                    fi
                done
        done
done

