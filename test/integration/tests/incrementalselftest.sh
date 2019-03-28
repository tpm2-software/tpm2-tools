#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2019, Sebastien LE STUM
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
alglist="$(yaml_get_kv "${temp}" \"remaining\")"
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
    tpm2_incrementalselftest "${aesmodes}" | grep -q "all tested"

    # Check testing of Hash algorithms
    tpm2_incrementalselftest "${hashalgs}" | grep -q "all tested"

    # Check testing of ECC methods
    tpm2_incrementalselftest "${eccmethods}" | grep -q "all tested"

    # Check testing of RSA methods
    tpm2_incrementalselftest "${rsamethods}" | grep -q "all tested"
fi

exit 0
