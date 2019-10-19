# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

start_up

cleanup() {

  rm -f policy.bin obj.pub pub.out primary.ctx

  if [ $(ina "$@" "keep-context") -ne 0 ]; then
    rm -f context.out
  fi

  if [ $(ina "$@" "no-shut-down") -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

cleanup "no-shut-down"

# Keep the algorithm specifiers mixed to test friendly and raw
# values.
for gAlg in `populate_hash_algs 'and alg != "keyedhash"'`; do
    for GAlg in rsa xor ecc aes; do
        echo tpm2_createprimary -Q -g $gAlg -G $GAlg -c context.out
        tpm2_createprimary -Q -g $gAlg -G $GAlg -c context.out
        cleanup "no-shut-down" "keep-context"
        for Atype in o e n; do
            tpm2_createprimary -Q -C $Atype -g $gAlg -G $GAlg -c context.out
            cleanup "no-shut-down" "keep-context"
        done
    done
done

policy_orig=f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988

#test for createprimary objects with policy authorization structures
echo -n "$policy_orig" | xxd -r -p > policy.bin

tpm2_createprimary -Q -C o -G rsa -g sha256 -c context.out -L policy.bin \
  -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin'

tpm2_readpublic -c context.out > pub.out

policy_new=$(yaml_get_kv pub.out "authorization policy")

test "$policy_orig" == "$policy_new"

# Test that -u can be specified to pass a TPMU_PUBLIC_ID union
# in this case TPM2B_PUBLIC_KEY_RSA (256 bytes of zero)
printf '\x00\x01' > ud.1
dd if=/dev/zero bs=256 count=1 of=ud.2
cat ud.1 ud.2 > unique.dat
tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c prim.ctx \
-a "restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|\
noda" -u unique.dat
test -f prim.ctx

# Test that -g/-G do not need to be specified.
tpm2_createprimary -Q -c context.out

# Test that -o does not need to be specified.
tpm2_createprimary -Q

# Test that creation data has the specified outside info
dd if=/dev/urandom of=outside.info bs=1 count=32

tpm2_createprimary -C o -c context.out --creation-data creation.data \
-q outside.info

xxd -p creation.data | tr -d '\n' | grep `xxd -p outside.info | tr -d '\n'`

# Test that selected pcrs digest is present in the creation data
tpm2_pcrread sha256:0 -o pcr_data.bin

tpm2_createprimary -C o -c context.out --creation-data creation.data \
-l sha256:0

xxd -p creation.data | tr -d '\n' | \
grep `cat pcr_data.bin | openssl dgst -sha256 -binary | xxd -p | tr -d '\n'`

# Test for session leaks
BEFORE=$(tpm2_getcap handles-loaded-session; tpm2_getcap handles-saved-session)
tpm2_createprimary -Q
AFTER=$(tpm2_getcap handles-loaded-session; tpm2_getcap handles-saved-session)
test "${BEFORE}" = "${AFTER}"

exit 0
