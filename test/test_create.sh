#!/bin/sh

pCtx=
gAlg=
GAlg=

rm create.error.log

for pCtx in `ls ctx.cpri*`
    do
    for gAlg in 0x04 0x0B 0x0C 0x0D 0x12
        do 
        for GAlg in 0x01 0x08 0x23 0x25
            do 
            ./tpm2_create -c $pCtx -g $gAlg -G $GAlg -o opu."$pCtx".g"$gAlg".G"$GAlg" -O opr."$pCtx".g"$gAlg".G"$GAlg"
            if [ $? != 0 ];then 
            echo "tpm2_create error: pCtx=$pCtx gAlg=$gAlg GAlg=$GAlg"
            echo "tpm2_create error: pCtx=$pCtx gAlg=$gAlg GAlg=$GAlg" >> create.error.log             
            fi
        done
    done
done

