# SPDX-License-Identifier: BSD-3-Clause

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
tpm2 incrementalselftest > "${temp}"
cat ${temp}
alglist="$(yaml_get_kv "${temp}" "remaining" || true)"
rm -f "${temp}"

# If the list of remaining algs is not empty, we can test
# the behaviour of tpm2 incrementalselftest and see
# each alg become scheduled and tested. If there are
# some leftovers, just print them
if [ -n "${alglist}" ]; then
    for i in ${alglist}; do
        if ! tpm2 incrementalselftest "${i}" ; then
            echo "${i} failed to be tested."
            exit 1
        fi
    done
    localtmp=$(mktemp)
    tpm2 incrementalselftest > "${localtmp}"
    alglist="$(yaml_get_kv "${localtmp}" "remaining" || true)"
    rm -f "${localtmp}"

    if [ -n "${alglist}" ]; then
        echo "Algorithm suite remaning : ${alglist}"
    else
        true
    fi
fi

# Finally just verify that every algorithm are
# effectively being already tested
aesmodes="$(populate_algs "details['encrypting'] and details['symmetric']")"
hashalgs="$(populate_algs "details['hash'] and not details['method'] \
                                        and not details['signing'] \
                                        and not details['symmetric'] \
                                        and alg is not None")"
eccmethods="$(populate_algs "details['signing'] and not details['hash'] \
and \"ec\" in alg")"
rsamethods="$(populate_algs "details['signing'] and not details['hash'] \
and \"rsa\" in alg")"

# Check testing of AES modes
tpm2 incrementalselftest ${aesmodes} | grep -q "complete"

# Check testing of Hash algorithms
tpm2 incrementalselftest ${hashalgs} | grep -q "complete"

# Check testing of ECC methods
tpm2 incrementalselftest ${eccmethods} | grep -q "complete"

# Check testing of RSA methods
tpm2 incrementalselftest ${rsamethods} | grep -q "complete"

exit 0
