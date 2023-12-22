# SPDX-License-Identifier: BSD-3-Clause

set -E
shopt -s expand_aliases

alias python=${PYTHON-python}

yaml_validate() {
    cmd=$1

    if test -z "$cmd"
    then
	python -c "import yaml,sys; yaml.safe_load(sys.stdin)"
    else
	python -c "import yaml,sys; y=yaml.safe_load(sys.stdin); $cmd"
    fi
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

    diff -u $evlog.yaml $base.out
    if [ $? -ne 0 ]; then
        echo "YAML output matching $evlog.yaml changed, set TEST_REGENERATE_OUTPUT=1 to re-create"
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
            echo "WARNING output matching $evlog.warn changed, set TEST_REGENERATE_OUTPUT=1 to re-create"

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
            echo "WARNING output for $evlog.warn unexpected, set TEST_REGENERATE_OUTPUT=1 to re-create"

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
expect_fail ${srcdir}/test/integration/fix
hex_file="${srcdir}/test/integration/fixtures/event-moklisttrusted-hex.yaml"
tool_file="${srcdir}/test/integration/fixtures/event-moklisttrusted.bin.yaml"

python << pyscript
import binascii
import sys
import yaml
import binascii

with open("$hex_file", 'r') as file:
    eventlog_hex = yaml.safe_load(file)

with open("$tool_file", 'r') as file:
    eventlog_tools = yaml.safe_load(file)

try:
    for i in range(len(eventlog_hex)):
        event_hex = eventlog_hex[i]['content']['event_data']
        event_bin = binascii.unhexlify(event_hex)
        event_tools = eventlog_tools['events'][i]
        if 'Event' in event_tools and 'String' in event_tools['Event']:
            event_string = event_bin.decode('ascii')
            event_tools = event_tools['Event']['String']
            if event_string != event_tools:
                print("Events are not equal:")
                print(str(event_tools))
                print(str(event_string))
                raise(Exception("Events are not equal"))
except Exception:
    sys.exit(1)
pyscript

exit $?
