#;**********************************************************************;
#
# Copyright (c) 2017, Alibaba Group
# Copyright (c) 2018, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

populate_hash_algs() {
    declare -A local name2hex=(
        ["sha1"]=0x04
        ["sha256"]=0x0B
        ["sha384"]=0x0C
        ["sha512"]=0x0D
        ["sm3_256"]=0x12
    )
    local algs="`tpm2_getcap -c algorithms | grep 'hash:\s*set$' -B 3 | awk '{ print $6 }' | xargs`"
    local algs_supported=""
    local t_alg

    # Filter out the hash algorithms not appropriate for the test.
    for t_alg in $algs; do
        [ ! ${name2hex[$t_alg]} ] && continue

        algs_supported="$t_alg $algs_supported"
    done

    local mode=${1:-"name"}
    local ret=""
    local let i=0

    for t_alg in $algs_supported; do
        if [ "$mode" = "hex" ]; then
            ret="$ret ${name2hex[$t_alg]}"
        elif [ "$mode" = "mixed" ]; then
            [ $i -eq 0 ] && ret="$ret $t_alg" || ret="$ret ${name2hex[$t_alg]}"
            let "i=$i^1"
        else
            echo "$algs_supported"
            return
        fi
    done

    echo "$ret"
}

# Return alg argument if supported by TPM.
hash_alg_supported() {
    local orig_alg="$1"
    local alg="$orig_alg"
    local algs_supported="`populate_hash_algs name`"
    local hex2name=(
        [0x04]="sha1"
        [0x0B]="sha256"
        [0x0C]="sha384"
        [0x0D]="sha512"
        [0x12]="sm3_256"
    )

    if [ -z "$alg" ]; then
        echo "$algs_supported"
        return
    fi

    if [ "$alg" = "${alg//[^0-9a-fA-FxX]/}" ]; then
        alg=${hex2name["$alg"]}
        [ -z "$alg" ] && return
    fi

    local t_alg
    for t_alg in $algs_supported; do
        if [ "$t_alg" = "$alg" ]; then
            echo "$orig_alg"
            return
        fi
    done
}

#
# Verifies that the contexts of a file path provided
# as the first argument loads as a YAML file.
#
function yaml_verify() {
python << pyscript
from __future__ import print_function

import sys
import yaml

with open("$1") as f:
    try:
        y = yaml.load(f)
    except yaml.YAMLError as exc:
        sys.exit(exc)
pyscript
}

#
# Given a file as argument 1, prints the value of the key
# provided as argument 2 and optionally argument 3 (for nested maps).
# Note that if key is a string, pass the quotes. This allows lookups
# on string or numerical keys.
#
function yaml_get_kv() {

third_arg=\"\"
if [ $# -eq 3 ]; then
  third_arg=$3
fi

python << pyscript
from __future__ import print_function

import sys
import yaml

with open("$1") as f:
    try:
        y = yaml.load(f)
        if $# == 3:
            print(y[$2][$third_arg])
        else:
            print(y[$2])
    except yaml.YAMLError as exc:
        sys.exit(exc)
pyscript
}

function recreate_info() {
    # TODO Add tmpdir location
    echo
    echo "--- To recreate this test run the following from: `pwd` ---"
    local a="export TPM2_ABRMD=\"$TPM2_ABRMD\" TPM2_SIM=\"$TPM2_SIM\""
    local b="PATH=\"$PATH\" TPM2_SIM_NV_CHIP=\"$TPM2_SIM_NV_CHIP\""
    local c="TPM2_TOOLS_TEST_FIXTURES=\"$TPM2_TOOLS_TEST_FIXTURES\""
    echo "#!/usr/bin/env bash"
    echo "$a $b $c"
    echo "$0"
    echo "--- EOF ---"
    echo
}

tpm2_test_cwd=""
function switch_to_test_dir() {
    tpm2_test_cwd=$(mktemp --directory --tmpdir=/tmp tpm2_test_XXXXXX)
    echo "creating simulator working dir: $tpm2_test_cwd"
    pushd "$tpm2_test_cwd"
    echo "Switched to CWD: $(pwd)"
}

function switch_back_from_test_dir() {
    popd
}

tpm2_sim_pid=""
tpm2_sim_port=""

tpm2_abrmd_pid=""
tpm2_tabrmd_opts=""
tpm2_tcti_opts=""
function start_sim() {

    tpm2_sim_port=`shuf -i 2321-65535 -n 1`

    local max_cnt=10

    while [ $max_cnt -gt 0 ]; do

        echo "Attempting to start simulator on port: $tpm2_sim_port"
        $TPM2_SIM -port $tpm2_sim_port &
        tpm2_sim_pid=$!
        sleep 1
        kill -0 "$tpm2_sim_pid"
        if [ $? -eq 0 ]; then
            local name="com.intel.tss2.Tabrmd${tpm2_sim_port}"
                        tpm2_tabrmd_opts="--session --dbus-name=$name --tcti=mssim:port=$tpm2_sim_port"
            echo "tpm2_tabrmd_opts: $tpm2_tabrmd_opts"

            tpm2_tcti_opts="abrmd:bus_type=session,bus_name=$name"
            echo "tpm2_tcti_opts: $tpm2_tcti_opts"
            echo "Started simulator in tmp dir: $tpm2_test_cwd"
            return 0
        else
            echo "Could not start simulator at port: $tpm2_sim_port"
            # Call wait to prevent zombies
            wait "$tpm2_sim_pid"
        fi

        echo "Shuffling port"
        tpm2_sim_port=`shuf -i 2321-65535 -n 1`

        echo "Decrementing max_cnt"
        let "max_cnt=max_cnt-1"
        echo "Tries left: $max_cnt"
    done;

    (>&2 echo "Could not start the tpm2 simulator \"$TPM2_SIM\", exit code: $?")

    return 1;
}

function start_abrmd() {

	if [ $UID -eq 0 ]; then
		tpm2_tabrmd_opts="--allow-root $tpm2_tabrmd_opts"
	fi

    echo "tpm2-abrmd command: $TPM2_ABRMD $tpm2_tabrmd_opts"
    $TPM2_ABRMD $tpm2_tabrmd_opts &
    tpm2_abrmd_pid=$!
    sleep 2
    kill -0 "$tpm2_abrmd_pid"
    if [ $? -ne 0 ]; then
        (>&2 echo "Could not start tpm2-abrmd \"$TPM2_ABRMD\", exit code: $?")
        kill -9 $tpm2_abrmd_pid
        return 1
    fi

    return 0
}

function start_up() {

    recreate_info

    switch_to_test_dir

    # Start the simulator
    echo "Starting the simulator"
    start_sim
    if [ $? -ne 0 ]; then
        exit 1;
    fi
    echo "Started the simulator"

    if [ "$1" != "no-abrmd" ]; then
        echo "Starting tpm2-abrmd"
        # Start tpm2-abrmd
        start_abrmd
        echo "Started tpm2-abrmd"
        echo "Setting TCTI to use abrmd"
        echo "export TPM2TOOLS_TCTI=\"$tpm2_tcti_opts\""
        export TPM2TOOLS_TCTI="$tpm2_tcti_opts"
    else
        export TPM2TOOLS_TCTI="socket:port=$tpm2_sim_port"
        echo "Not starting tpm2-abrmd"
        echo "Setting TCTI to use mssim"
        echo "export TPM2TOOLS_TCTI=\"socket:port=$tpm2_sim_port\""
        export TPM2TOOLS_TCTI="socket:port=$tpm2_sim_port"
    fi

    echo "Running tpm2_clear"
    tpm2_clear
    if [ $? -ne 0 ]; then
        exit 1
    fi
}

function shut_down() {

    echo "Shutting down"

    switch_back_from_test_dir

    fail=0
    if [ -n "$tpm2_abrmd_pid" ]; then
        kill -9 "$tpm2_abrmd_pid"
        if [ $? -ne 0 ]; then
            (>&2 echo "ERROR: could not kill tpm2_abrmd on pid: $tpm2_abrmd_pid")
            fail=1
        fi
    fi
    tpm2_abrmd_pid=""

    if [ -n "$tpm2_sim_pid" ]; then
        kill -9 "$tpm2_sim_pid"
        if [ $? -ne 0 ]; then
            (>&2 echo "ERROR: could not kill tpm2 simulator on pid: $tpm2_sim_pid")
            fail=1
        fi
    fi
    tpm2_sim_pid=""

    echo "Removing sim dir: $tpm2_test_cwd"
    rm -rf $tpm2_test_cwd 2>/dev/null

    if [ $fail -ne 0 ]; then
        exit 1
    fi
}

#
# Set the default EXIT handler to always shut down, tests
# can override this.
#
trap shut_down EXIT

#
# Set the default on ERR handler to print the line number
# and failed command.
#
onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

function ina() {
    local n=$#
    local value=${!n}
    for ((i=1;i < $#;i++)) {
        if [ "${!i}" == "${value}" ]; then
            return 0
        fi
    }
    return 1
}
