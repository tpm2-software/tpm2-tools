# SPDX-License-Identifier: BSD-3-Clause

yaml_validate() {
    python -c 'import yaml,sys; yaml.safe_load(sys.stdin)'
}

expect_fail() {
    $@
    if [ $? -eq 0 ]; then
        echo "failing test case passed"
        exit 1;
    fi
}
expect_pass() {
    $@ | yaml_validate
    if [ $? -ne 0 ]; then
        echo "passing test case failed"
        exit 1;
    fi
}

expect_fail tpm2 eventlog
expect_fail tpm2 eventlog foo
expect_fail tpm2 eventlog foo bar
expect_fail tpm2 eventlog ${srcdir}/test/integration/fixtures/event-bad.bin

expect_pass tpm2 eventlog ${srcdir}/test/integration/fixtures/specid-vendordata.bin
expect_pass tpm2 eventlog ${srcdir}/test/integration/fixtures/event.bin
expect_pass tpm2 eventlog ${srcdir}/test/integration/fixtures/event-uefivar.bin
expect_pass tpm2 eventlog ${srcdir}/test/integration/fixtures/event-uefiaction.bin
expect_pass tpm2 eventlog ${srcdir}/test/integration/fixtures/event-uefiservices.bin
expect_pass tpm2 eventlog ${srcdir}/test/integration/fixtures/event-uefi-sha1-log.bin
expect_pass tpm2 eventlog ${srcdir}/test/integration/fixtures/event-bootorder.bin

exit $?
