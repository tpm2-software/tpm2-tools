#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;
#
# Copyright (c) 2019, Sebastien LE STUM
# All rights reserved.
#
#;**********************************************************************;

source helpers.sh

cleanup() {
    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

# Perform simple selftest
tpm2_selftest

# Perform full selftest
tpm2_selftest --fulltest

exit 0
