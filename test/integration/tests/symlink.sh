# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

TMP="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP"
    if [ "$1" != "no-shut-down" ]; then
	shut_down
    fi
}
trap cleanup EXIT

start_up

#
# Positive tests:
#
fail=0
TPM2_TOOL="$(which tpm2)"

if [ -z "$TPM2_TOOL" ]; then
    echo "unable to locate tpm2 tool"
    fail=1
fi

#echo "Using $TPM2_TOOL"

#
# Disabling this test and leaving a note for traceability because
# disabling/ deleting tests without rational is a bad thing.
#
# Executing tpm2 without argument should now execute the man-page.
#
## no arguments should produce at least ten lines of output
#NUM_TOOLS=$(tpm2 2>&1 | wc -l)
#if [ -z "$NUM_TOOLS" ] || [ "$NUM_TOOLS" -lt 10 ]; then
#    echo "tpm2 with no arguments did not produce list of tools"
#    fail=1
#fi


# busybox style
if ! tpm2 readclock &>/dev/null ; then
    echo "busybox style failed"
    fail=1
fi

# with tpm2_ prefix
ln -s "$TPM2_TOOL" "$TMP/tpm2_readclock" 
if ! "$TMP/tpm2_readclock" &>/dev/null ; then
    echo "tpm2_ prefix style failed"
    fail=1
fi

# without prefix
ln -s "$TPM2_TOOL" "$TMP/readclock" 
if ! "$TMP/readclock" &>/dev/null ; then
    echo "no prefix style failed"
    fail=1
fi

#
# Negative tests
#

# command not found, as busybox style
if tpm2 bad-command &>/dev/null ; then
    echo "Expected 'tmp2 bad-command' to fail."
    fail=1
fi

# command not found, with tpm2_ prefix
ln -s "$TPM2_TOOL" "$TMP/tmp2_bad-command"
if "$TMP/tmp2_bad-command" &>/dev/null ; then
    echo "Expected 'tmp2_bad-command' to fail."
    fail=1
fi

# command not found, without tpm2_ prefix
ln -s "$TPM2_TOOL" "$TMP/bad-command"
if "$TMP/bad-command" &>/dev/null ; then
    echo "Expected 'bad-command' to fail."
    fail=1
fi

exit "$fail"
