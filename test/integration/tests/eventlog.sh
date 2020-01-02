# SPDX-License-Identifier: BSD-3-Clause

expect_fail() {
    $@
    if [ $? -eq 0 ]; then
        echo "failing test case passed"
        exit 1;
    fi
}

expect_fail tpm2_eventlog
expect_fail tpm2_eventlog foo
expect_fail tpm2_eventlog foo bar
expect_fail tpm2_eventlog ${srcdir}/test/integration/fixtures/event-bad.bin
tpm2_eventlog ${srcdir}/test/integration/fixtures/event.bin
if [ $? -ne 0 ]; then
    echo "passing test case failed"
fi

exit $?
