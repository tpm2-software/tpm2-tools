# SPDX-License-Identifier: BSD-3-Clause

set -E
shopt -s expand_aliases

alias python=${PYTHON-python}

yaml_validate() {
    python -c 'import yaml,sys; yaml.safe_load(sys.stdin)'
}

expect_fail() {
    tpm2 eventlog $@
    if [ $? -eq 0 ]; then
        echo "failing test case passed"
        exit 1;
    fi
}

expect_pass() {
    evlog=$1
    shift

    base=$(basename $evlog)
    tpm2 eventlog $@ $evlog 1> $base.out 2> $base.err

    ret=0

    yaml_validate < $base.out
    if [ $? -ne 0 ]; then
        echo "YAML parsing failed"
        ret=1
    fi

    diff $evlog.yaml $base.out
    if [ $? -ne 0 ]; then
        echo "YAML output changed"

        if test "$TEST_REGENERATE_OUTPUT" = "1"
        then
            cp $base.out $evlog.yaml
        else
            ret=1
        fi
    fi

    if test -f $evlog.warn
    then
        diff $evlog.warn $base.err
        if [ $? -ne 0 ]; then
            echo "WARNING output changed"

            if test "$TEST_REGENERATE_OUTPUT" = "1"
            then
                cp $base.err $evlog.warn
            else
                ret=1
            fi
        fi
    else
        if test -s $base.err
        then
            cat $base.err
            echo "WARNING output unexpected"

            if test "$TEST_REGENERATE_OUTPUT" = "1"
            then
                cp $base.err $evlog.warn
            else
                ret=1
            fi
        fi
    fi

    rm $base.out $base.err
    if test $ret != 0
    then
        exit $ret
    fi
}

expect_fail
expect_fail foo
expect_fail foo bar
expect_fail ${srcdir}/test/integration/fixtures/event-bad.bin

expect_pass ${srcdir}/test/integration/fixtures/specid-vendordata.bin
expect_pass ${srcdir}/test/integration/fixtures/event.bin
expect_pass ${srcdir}/test/integration/fixtures/event-uefivar.bin
expect_pass ${srcdir}/test/integration/fixtures/event-uefiaction.bin
expect_pass ${srcdir}/test/integration/fixtures/event-uefiservices.bin
expect_pass ${srcdir}/test/integration/fixtures/event-uefi-sha1-log.bin
expect_pass ${srcdir}/test/integration/fixtures/event-bootorder.bin
expect_pass ${srcdir}/test/integration/fixtures/event-postcode.bin

# Make sure that --eventlog-version=2 works on complete TPM2 logs
expect_pass ${srcdir}/test/integration/fixtures/event-arch-linux.bin --eventlog-version=2
expect_pass ${srcdir}/test/integration/fixtures/event-gce-ubuntu-2104-log.bin --eventlog-version=2
expect_pass ${srcdir}/test/integration/fixtures/event-sd-boot-fedora37.bin --eventlog-version=2
expect_pass ${srcdir}/test/integration/fixtures/event-moklisttrusted.bin --eventlog-version=2

exit $?
