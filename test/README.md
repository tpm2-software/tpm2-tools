**these are some scripts for the testing of TPM (Trusted Platform Module) 2.0 tools **

Below are script instructions:
##1: integration testing
test_smoking.sh is a quick & brief testing for all tpm-tools.
test_all.sh runs all separated .sh.

##2: separated testing
There are some separated .sh for each of tpm2-tool. Name convention is test_tpm2_xxx.sh.

##3: algorithm testing
Named as test_algs_tpm2_XXX.sh, test all algorithms involved in the parameters of tpm2-tools.
A part of test_tpm2_XXX_all.sh also contain algorithm testing.     

##4: others 
test_tpm2_XXX_func.sh for adding some test cases in furture.   

##Condition and Operation instructions:
1.TPM is initialized
2.install tpm2-tools
3.must start resourcemgr before run all test scripts
4.clean up all log files
5.run xxx.sh for automatic test
6.results record in XXX_pass.log or XXX_fail.log 

