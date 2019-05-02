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
    rm -f pcrs.out

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_pcrlist > pcrs.out
yaml_verify pcrs.out

tpm2_pcrlist -Q -g 0x04

tpm2_pcrlist -Q -L 0x04:17,18,19+sha256:0,17,18,19 -o pcrs.out

test -e pcrs.out

tpm2_pcrlist -Q -s

exit 0
