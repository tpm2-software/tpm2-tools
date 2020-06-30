# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

###this script use for test the implementation tpm2 createpolicy

cleanup() {
    rm -f pcr.in policy.out

    if [ "$1" != "no-shut-down" ]; then
      shut_down
    fi
}
trap cleanup EXIT

start_up

declare -A digestlengths=\
([sha1]=20
 [sha256]=32)
declare -A expected_policy_digest=\
([sha1]=f28230c080bbe417141199e36d18978228d8948fc10a6a24921b9eba6bb1d988
 [sha256]=33e36e786c878632494217c3f490e74ca0a3a122a8a4f3c5302500df3b32b3b8)

tpm2 pcrread -V sha1

for halg in ${!digestlengths[@]}
do
    cleanup "no-shut-down"

    # Create file containing expected PCR value
    head -c $((${digestlengths[$halg]} - 1)) /dev/zero > pcr.in
    echo -n -e '\x03' >> pcr.in

    tpm2 createpolicy --policy-pcr -l $halg:0 -f pcr.in -L policy.out

    # Test the policy creation hashes against expected
    if [ $(xxd -p policy.out | tr -d '\n' ) != \
    "${expected_policy_digest[${halg}]}" ]; then
        echo "Failure: Creating Policy Digest with PCR policy for index 0 and \
        ${halg} pcr index hash"
        echo "Got: $(xxd -p policy.out | tr -d '\n')"
        echo "Expected: ${expected_policy_digest[${halg}]}"
        exit 1
    fi
done

exit 0
