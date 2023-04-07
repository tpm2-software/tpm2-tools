# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

nv_test_index=0x01500001

cleanup() {
  tpm2 nvundefine -Q -C o $nv_test_index 2>/dev/null || true
  tpm2 flushcontext -t
  tpm2 flushcontext -l
  tpm2 flushcontext -s

  rm -f session.ctx

  if [ "$1" != "no-shut-down" ]; then
     shut_down
  fi
}

# Data written to NV index --> 129 or -127
operandA=0x81
# Data specified in command line options for comparison
operandB=0

evaluate_failing_test_case() {
  tpm2 startauthsession -S session.ctx --policy-session
  trap - ERR
  echo $operandA | xxd -r -p | \
  tpm2 policynv -S session.ctx -i- -P nvpass $nv_test_index eq
  if [ $? != 1 ];then
   echo "FAIL: Expected tpm2 policynv to fail!"
   exit 1
  fi
  trap onerror ERR
  tpm2 flushcontext session.ctx
}

evaluate_passing_test_case() {
    tpm2 startauthsession -S session.ctx --policy-session
    if [[ ${1:0:1} == "s" ]]; then
        echo "Test sign: $1 $operandA $operandB"
        # check whether sign compare fails with 0x126
        trap - ERR
        output=$(echo $operandB | xxd -r -p | \
                     tpm2 policynv -S session.ctx -i- -P nvpass $nv_test_index $1 2>&1)
        result=$?
        if [ $result != 0 ] && echo $output | grep "ErrorCode.*0126" > /dev/null
        then
            echo "This test failed due to a TPM bug regarding signed comparison as described"
            echo "in TCG's Errata for TCG Trusted Platform Module Library Revision 1.59 Version 1.4,"
            echo "Section 2.5 TPM_EO – two’s complement"
            tpm2 flushcontext session.ctx
            skip_test
        else
            if [ $result != 0 ]; then
                tpm2 flushcontext session.ctx
                exit 1
            fi
        fi
        tpm2 flushcontext session.ctx
        trap onerror ERR
    else
        echo $operandB | xxd -r -p | \
            tpm2 policynv -S session.ctx -i- -P nvpass $nv_test_index $1
        tpm2 flushcontext session.ctx
    fi
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear

# Perform any comparison operation on an undefined NV index --> Should fail
evaluate_failing_test_case

# Define an NV index
tpm2 nvdefine -C o -p nvpass $nv_test_index -a "authread|authwrite" -s 1

# Perform any comparison operation on an unwritten NV index --> Should fail
evaluate_failing_test_case

# Write data to NV index --> This is operandA
echo $operandA | xxd -r -p | tpm2 nvwrite -P nvpass -i- $nv_test_index

# Perform comparison operation "eq"
operandB=0x81
evaluate_passing_test_case eq

# Perform comparison operation "neq"
operandB=0x80
evaluate_passing_test_case neq

# Perform comparison operation "ugt"
operandB=0x80
evaluate_passing_test_case ugt

# Perform comparison operation "ult"
operandB=0x82
evaluate_passing_test_case ult

# Perform comparison operation "uge"
operandB=0x80
evaluate_passing_test_case uge
operandB=0x81
evaluate_passing_test_case uge

# Perform comparison operation "ule"
operandB=0x82
evaluate_passing_test_case ule
operandB=0x81
evaluate_passing_test_case ule

# Perform comparison operation "bs"
operandB=0x81
evaluate_passing_test_case bs

# Perform comparison operation "bc"
operandB=0x7E
evaluate_passing_test_case bc

operandA=0xfe # -1
echo $operandA | xxd -r -p | tpm2 nvwrite -P nvpass -i- $nv_test_index

# Perform comparison operation "sgt"
operandB=0xfd # -2
evaluate_passing_test_case sgt

# Perform comparison operation "slt"
operandB=0xff # 0
evaluate_passing_test_case slt

# Perform comparison operation "sle"
operandB=0xff #0
evaluate_passing_test_case sle
operandB=0xfe # -1
evaluate_passing_test_case sle

# Perform comparison operation "sge"
operandB=0xfd # -2
evaluate_passing_test_case sge
operandB=0xfe # -1
evaluate_passing_test_case sge

exit 0
