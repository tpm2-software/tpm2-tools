#!/bin/bash
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

function filter_algs_by() {

python << pyscript
from __future__ import print_function

import sys
import yaml

with open("$1") as f:
    try:
        y = yaml.load(f)
        for alg, details in y.iteritems():
            if $2:
                print(alg)
    except yaml.YAMLError as exc:
        sys.exit(exc)
pyscript
}

populate_algs() {
    algs="$(mktemp)"
    tpm2_getcap -c algorithms > "${algs}"
    filter_algs_by "${algs}" "${1}"
    rm "${algs}"
}

populate_hash_algs() {
    populate_algs "details['hash'] and not details['method'] and not details['symmetric'] and not details['signing'] $1"
}

# Return alg argument if supported by TPM.
hash_alg_supported() {
    local orig_alg="$1"
    local alg="$orig_alg"
    local algs_supported

    algs_supported="$(populate_hash_algs name)"
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
    echo "--- To recreate this test run the following from: $(pwd) ---"
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
tpm2_mssim_tcti_expected_port=""
tpm2_abrmd_pid=""
tpm2_tabrmd_opts=""
tpm2_tcti_opts=""
function start_sim() {
    local max_cnt=10

    # Do not rely on whether netstat is present or not and directly fetch
    # data in relevent /proc file
    tcpports="$(tail -n +2 /proc/net/tcp 2>/dev/null | awk '{print $2}' | cut -d':' -f2)"
    tcpports+=" $(tail -n +2 /proc/net/tcp 2>/dev/null | awk '{print $3}' | cut -d':' -f2)"
    tcpports+=" $(tail -n +2 /proc/net/tcp6 2>/dev/null | awk '{print $2}' | cut -d':' -f2)"
    tcpports+=" $(tail -n +2 /proc/net/tcp6 2>/dev/null | awk '{print $3}' | cut -d':' -f2)"
    openedtcpports=""

    for i in ${tcpports}; do
        openedtcpports+="$(printf "%d " 0x${i} 2>/dev/null)"
    done

    # If either the requested simulator port or the port that will be used
    # by mssim TCTI which is tpm2_sim_port + 1 is occupied (ESTABLISHED, TIME_WAIT, etc...),
    # just continue up to 10 retries
    # (See : https://github.com/tpm2-software/tpm2-tss/blob/master/src/tss2-tcti/tcti-mssim.c:559)
    while [ $max_cnt -gt 0 ]; do
        tpm2_sim_port="$(shuf -i 2321-65534 -n 1)"
        tpm2_mssim_tcti_expected_port=$((tpm2_sim_port + 1))
        if grep -qE " (${tpm2_sim_port}|${tpm2_mssim_tcti_expected_port}) " <<< "${openedtcpports}"; then
            echo "Selected TCP port tuple (${tpm2_sim_port}, ${tpm2_mssim_tcti_expected_port}) is currently used"
            let "max_cnt=max_cnt-1"
            echo "Tries left: $max_cnt"
        else
            break
        fi
    done

    [ $max_cnt -eq 0 ] && {
        echo "Maximum attempts reached. Aborting"
        return 1
    }

    echo "Attempting to start simulator on port: $tpm2_sim_port"
    $TPM2_SIM -port $tpm2_sim_port &
    tpm2_sim_pid=$!
    sleep 1
    if kill -0 "$tpm2_sim_pid"; then
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

    (>&2 echo "Could not start the tpm2 simulator \"$TPM2_SIM\", exit code: $?")

    return 1;
}

function start_abrmd() {

    if [ -z "$TPM2_SIM" ]; then
        local tcti="device"
        if [ -n "$TPM2_DEVICE" ]; then
            tcti="device:$TPM2_DEVICE"
        fi

        local name="com.intel.tss2.Tabrmd.device"
        tpm2_tabrmd_opts="--session --dbus-name=$name --tcti=$tcti"
        tpm2_tcti_opts="abrmd:bus_type=session,bus_name=$name"
    fi

    if [ $UID -eq 0 ]; then
        tpm2_tabrmd_opts="--allow-root $tpm2_tabrmd_opts"
    fi

    echo "tpm2-abrmd command: $TPM2_ABRMD $tpm2_tabrmd_opts"
    $TPM2_ABRMD $tpm2_tabrmd_opts &
    tpm2_abrmd_pid=$!
    sleep 2

    if ! kill -0 "$tpm2_abrmd_pid"; then
        (>&2 echo "Could not start tpm2-abrmd \"$TPM2_ABRMD\", exit code: $?")
        kill -9 $tpm2_abrmd_pid
        return 1
    fi

    return 0
}

function start_up() {

    recreate_info

    switch_to_test_dir

    if [ -n "$TPM2_SIM" ]; then
        # Start the simulator
        echo "Starting the simulator"
        start_sim || exit 1
        echo "Started the simulator"
    fi

    if [ -n "$TPM2_ABRMD" ]; then
        echo "Starting tpm2-abrmd"
        # Start tpm2-abrmd
        start_abrmd || exit 1
        echo "Started tpm2-abrmd"
        echo "Setting TCTI to use abrmd"
        echo "export TPM2TOOLS_TCTI=\"$tpm2_tcti_opts\""
        export TPM2TOOLS_TCTI="$tpm2_tcti_opts"
    elif [ -n "$TPM2_SIM" ]; then
        echo "Not starting tpm2-abrmd"
        echo "Setting TCTI to use mssim"
        echo "export TPM2TOOLS_TCTI=\"mssim:port=$tpm2_sim_port\""
        export TPM2TOOLS_TCTI="mssim:port=$tpm2_sim_port"

        echo "Running tpm2_startup -c"
        tpm2_startup -c
    else
        if [ -n "$TPM2_DEVICE" ]; then
            export TPM2TOOLS_TCTI="device:$TPM2_DEVICE"
        else
            export TPM2TOOLS_TCTI="device"
        fi
    fi

    echo "Running tpm2_clear"

    if ! tpm2_clear; then
        exit 1
    fi
}

function shut_down() {

    echo "Shutting down"

    switch_back_from_test_dir

    fail=0
    if [ -n "$tpm2_abrmd_pid" ]; then
        if kill -0 "$tpm2_abrmd_pid"; then
            if ! kill -9 "$tpm2_abrmd_pid"; then
                (>&2 echo "ERROR: could not kill tpm2_abrmd on pid: $tpm2_abrmd_pid")
                fail=1
            fi
        else
            (>&2 echo "WARNING: tpm2_abrmd already stopped ($tpm2_abrmd_pid)")
        fi
    fi
    tpm2_abrmd_pid=""

    if [ -n "$tpm2_sim_pid" ]; then
        if kill -0 "$tpm2_sim_pid"; then
            if ! kill -9 "$tpm2_sim_pid"; then
                (>&2 echo "ERROR: could not kill tpm2 simulator on pid: $tpm2_sim_pid")
                fail=1
            fi
        else
            (>&2 echo "WARNING: TPM simulator already stopped ($tpm2_sim_pid)")
        fi
    fi
    tpm2_sim_pid=""

    echo "Removing sim dir: $tpm2_test_cwd"
    rm -rf "$tpm2_test_cwd" 2>/dev/null

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
