# SPDX-License-Identifier: BSD-3-Clause

###this script use for test the implementation tpm2 dictionarylockout

source helpers.sh

out=out.yaml

cleanup() {
    rm -f $out
    shut_down
}
trap cleanup EXIT

start_up

tpm2 dictionarylockout -Q -V -c &>/dev/null

tpm2 dictionarylockout -s -n 5 -t 6 -l 7

tpm2 getcap properties-variable > $out
v=$(yaml_get_kv "$out" "TPM2_PT_MAX_AUTH_FAIL")
if [ $v -ne 5 ];then
  echo "Failure: setting up the number of allowed tries in the lockout \
  parameters"
  exit 1
fi

v=$(yaml_get_kv "$out" "TPM2_PT_LOCKOUT_INTERVAL")
if [ $v -ne 6 ];then
  echo "Failure: setting up the lockout period in the lockout parameters"
  exit 1
fi

v=$(yaml_get_kv "$out" "TPM2_PT_LOCKOUT_RECOVERY")
if [ $v -ne 7 ];then
  echo "Failure: setting up the lockout recovery period in the lockout \
  parameters"
  exit 1
fi

exit 0
