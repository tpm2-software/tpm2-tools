# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

# We don't need a TPM for this test, so unset the EXIT handler.
trap - EXIT

# Since this only tests rc_decode tool it on FreeBSD
if [ "$OS" == "FreeBSD" ]; then
    exit 0
fi

#
# codes was generated from the TPM2_RC constants in:
# https://github.com/tpm2-software/tpm2-tss/blob/master/include/sapi/tss2_tpm2 types.h#L68
# Some of these may not be used correctly, which is OK, as tpm2 rc_decode never
# fails and should attempt to decode it or print some unknown status. This gives
# us coverage for both known and unknown/malformed inputs.
#
# Details on error code encoding can be found at:
# Section 6.6.2 of t "Trusted Platform Module Library Part 2: Structures Family “2.0” Level 00 Revision 01.38"
#  - https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
#
declare -A codes

tss2_tpm2_types=''
for dir in "$(pkg-config --variable includedir tss2-esys)" \
/usr/local/include /usr/include; do
    if [ -f "$dir/tss2/tss2_tpm2_types.h" ]; then
        tss2_tpm2_types="$dir/tss2/tss2_tpm2_types.h"
        break
    fi
done

if [ -z "$tss2_tpm2_types" ]; then
    echo "Could not find TSS2 headers"
    exit 1
fi

# Populate the main TPM2_RC values
eval $(grep -Po "^#define \K(TPM2_RC.*)" "$tss2_tpm2_types" \
          | grep -v '+' \
          | sed "s%/*[^/]*/$%%g" \
          | sed "s%[[:space:]]*((TPM2_RC)[[:space:]]*%=%g" \
          | sed "s%)%%g")

# Generate the TPM2_RC array based on TSS2 header
varlist="$(sed -rn "s%^#define (TPM2_RC_[^[:space:]]*)[[:space:]]*\(\(TPM2_RC\) \((TPM2_RC[^\)]*)[^/]*/\* ([^\*]*) \*/%\1=\$\(\(\2\)\):\3%p" "$tss2_tpm2_types")"
while IFS='=' read key value; do
    codes[${key}]="${value}"
done <<< "${varlist}"

fail=0

for key in "${!codes[@]}"; do
    value="$(printf '0x%03x' "$(eval echo ${codes[$key]%%:*})")"
    expected_msg="${codes[$key]##*:}"
    received_msg="$(tpm2 rc_decode ${value} | cut -d':' -f3)"

    if ! grep -iq "${received_msg# }" <<< "${expected_msg}"; then
        echo "$value raised an invalid error message"
        echo "      - Expected : ${expected_msg}"
        echo "      - Seen     : ${received_msg# }"
        fail=1
    fi
done

#
# Negative tests
#
if tpm2 rc_decode 0x6666329840938498293849238 &>/dev/null; then
    echo "Expected \"$cmd\" to fail."
    fail=1
else
    true
fi

exit "$fail"
