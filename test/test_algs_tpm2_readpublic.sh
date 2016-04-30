 #!/bin/bash
 context_p=
 halg=

ctx_count=`ls |grep -c context_load`
if [ $ctx_count -le 1 ];then
	echo "we should execute test_algs.sh first!"
	wait 5
    ./test_algs.sh
fi
 rm test_readpublic_*.log

 for  context_p in `ls context_load*`
   do
     ./tpm2_readpublic -c $context_p  -o rd-opu_"$context_p"
     if [ $? != 0 ];then
     echo "readpublic for "$context_p" fail, pelase check the environment or  parameters!"
     echo "readpublic for "$context_p" fail" >>test_readpublic_error.log
     else
     echo "readpublic for "$context_p"  pass" >>test_readpublic__pass.log
    fi

  done

