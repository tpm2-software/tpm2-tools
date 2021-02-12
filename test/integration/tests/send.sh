# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

# assume this script is run from the test/ directory
TPM2_COMMAND_FILE="${abs_srcdir}/test/integration/fixtures/get-capability-tpm-prop-fixed.bin"

start_up

if [ ! -f "${TPM2_COMMAND_FILE}" ]; then
    echo "No TPM2 command file, cannot run $0"
    exit 1
fi

# check default stdin(file fd)/stdout
tpm2 send < "${TPM2_COMMAND_FILE}" > /dev/null

# check default stdin(pipe fd) with output file
cat ${TPM2_COMMAND_FILE} | tpm2 send -o /dev/null

# check -o out and argument file input
tpm2 send -o /dev/null "${TPM2_COMMAND_FILE}"

exit 0
