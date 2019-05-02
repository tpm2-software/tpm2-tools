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

tempfile=$(mktemp)

# Verify that tests have succeeded
tpm2_gettestresult > "${tempfile}"
yaml_get_kv "${tempfile}" \"status\" | grep "success"

exit 0
