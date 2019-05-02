#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
# All rights reserved.
#
#;**********************************************************************;

source helpers.sh

cleanup() {
    rm -f random.out

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

# test file output
tpm2_getrandom -o random.out 32

#test stdout
tpm2_getrandom 4 > random.out

yaml_verify random.out

# negative tests
trap - ERR

# larger than any known hash size should fail
tpm2_getrandom 2000 &> /dev/null
if [ $? -eq 0 ]; then
    echo "tpm2_getrandom should fail with too big of request"
    exit 1
fi

# verify that tpm2_getrandom requires a TCTI
./tools/tpm2_listpersistent -T none &> /dev/null
if [ $? -eq 0 ]; then
    echo "tpm2_getrandom should fail with tcti: \"none\""
    exit 1
fi


exit 0
