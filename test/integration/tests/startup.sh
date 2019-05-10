#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

start_up

tpm2_startup --clear

tpm2_startup

exit 0
