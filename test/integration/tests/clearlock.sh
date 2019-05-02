#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;
#
# Copyright (c) 2017, Emmanuel Deloget <logout@free.fr>
# Copyright (c) 2018, Intel Corporation
# All rights reserved.
#
#;**********************************************************************;

source helpers.sh

cleanup() {
    tpm2_clearlock -c -p

    shut_down
}
trap cleanup EXIT

start_up

tpm2_clearlock

tpm2_clearlock -c -p

tpm2_clear

exit 0
