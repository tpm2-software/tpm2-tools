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

# Get the list of remaining algs to be tested
temp=$(mktemp)
tpm2_incrementalselftest > "${temp}"
cat ${temp}
alglist="$(yaml_get_kv "${temp}" \"remaining\" || true)"
rm -f "${temp}"

# If the list of remaining algs is not empty, we can test
# the behaviour of tpm2_incrementalselftest and see
# each alg become scheduled and tested. If there are
# some leftovers, just print them
#
# Else just verify that the command didn't «lie» to us
# and every algorithm are effectively being already
# tested
if [ -n "${alglist}" ]; then
    for i in ${alglist}; do
        if ! tpm2_incrementalselftest "${i}" ; then
            echo "${i} failed to be tested."
            exit 1
        fi
    done
    localtmp=$(mktemp)
    tpm2_incrementalselftest > "${localtmp}"
    alglist="$(yaml_get_kv "${localtmp}" \"remaining\" || true)"
    rm -f "${localtmp}"

    if [ -n "${alglist}" ]; then
        echo "Algorithm suite remaning : ${alglist}"
    else
        true
    fi
else
    aesmodes="$(populate_algs "details['encrypting'] and details['symmetric']")"
    hashalgs="$(populate_algs "details['hash'] and not details['method'] \
                                            and not details['signing'] \
                                            and not details['symmetric'] \
                                            and alg is not None")"
    eccmethods="$(populate_algs "details['signing'] and not details['hash'] and \"rsa\" not in alg")"
    rsamethods="$(populate_algs "details['signing'] and not details['hash'] and \"ec\" not in alg")"

    # Check testing of AES modes
    tpm2_incrementalselftest ${aesmodes} | grep -q "all tested"

    # Check testing of Hash algorithms
    tpm2_incrementalselftest ${hashalgs} | grep -q "all tested"

    # Check testing of ECC methods
    tpm2_incrementalselftest ${eccmethods} | grep -q "all tested"

    # Check testing of RSA methods
    tpm2_incrementalselftest ${rsamethods} | grep -q "all tested"
fi

exit 0
