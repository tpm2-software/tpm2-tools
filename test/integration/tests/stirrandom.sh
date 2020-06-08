# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

goodfile=$(mktemp)
bigfile=$(mktemp)
{
    dd if=/dev/urandom of="${bigfile}" bs=1 count=256
    dd if=/dev/urandom of="${goodfile}" bs=1 count=42
} &>/dev/null

cleanup() {
    if [ "$1" != "no-shut-down" ]; then
        shut_down
        rm -f "${bigfile}"
        rm -f "${goodfile}"
    fi
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

# Sending bytes from stdin (pipe)
echo -n "return 4" | tpm2 stirrandom -V 2>&1 1>/dev/null | \
grep -q "Submitting 8 bytes to TPM"

# Sending bytes from stdin (file)
tpm2 stirrandom -V < "${goodfile}" 2>&1 1>/dev/null | \
grep -q "Submitting 42 bytes to TPM"

# Sending bytes from a file path
tpm2 stirrandom "${goodfile}" -V 2>&1 1>/dev/null | \
grep -q "Submitting 42 bytes to TPM"

# Try to read more than 128 bytes from file and get an error
if tpm2 stirrandom "${bigfile}"; then
    echo "tpm2 stirrandom didn't fail on exceeding requested size"
    exit 1
else
    true
fi

exit 0
