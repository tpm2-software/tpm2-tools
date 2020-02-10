# SPDX-License-Identifier: BSD-3-Clause

expect_fail() {
    $@
    if [ $? -eq 0 ]; then
        echo "failing test case passed"
        exit 1;
    fi
}
expect_pass() {
    $@
    if [ $? -ne 0 ]; then
        echo "passing test case failed"
        exit 1;
    fi
}
expect_fail tpm2_eventlog
expect_fail tpm2_eventlog foo
expect_fail tpm2_eventlog foo bar
expect_fail tpm2_eventlog ${srcdir}/test/integration/fixtures/event-bad.bin

expect_pass tpm2_eventlog ${srcdir}/test/integration/fixtures/specid-vendordata.bin
expect_pass tpm2_eventlog ${srcdir}/test/integration/fixtures/event.bin
expect_pass tpm2_eventlog ${srcdir}/test/integration/fixtures/event-uefivar.bin
expect_pass tpm2_eventlog ${srcdir}/test/integration/fixtures/event-uefiaction.bin
expect_pass tpm2_eventlog ${srcdir}/test/integration/fixtures/event-uefiservices.bin

exit $?
